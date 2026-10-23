import { redactTokens, redactUrl } from '../shared/redact';
import { sanitizeText } from '../shared/sanitize';
import type {
  ConfidenceLevel,
  Detection,
  DomPropertyQuery,
  DomQuery,
  Evidence,
  EvidenceType,
  PageSnapshot,
} from '../types';
import { CATEGORY_ORDER, type Rule, type Signature } from './signature';
import { SIGNATURES } from './signatures';
import { isExactVersion, mergeVersionCandidates, normalizeVersion } from './version';

const MAX_EVIDENCE_PER_RULE = 2;
const EVIDENCE_MAX_LENGTH = 160;

export interface CollectionPlan {
  globals: string[];
  dom: DomQuery[];
  domProperties: DomPropertyQuery[];
}

export function domQueryId(signatureId: string, index: number): string {
  return `${signatureId}#${index}`;
}

/** Everything the page collectors must look up for the given signatures. */
export function buildCollectionPlan(signatures: Signature[] = SIGNATURES): CollectionPlan {
  const globals = new Set<string>();
  const dom: DomQuery[] = [];
  const domProperties: DomPropertyQuery[] = [];
  for (const sig of signatures) {
    for (const path of Object.keys(sig.rules.globals ?? {})) globals.add(path);
    sig.rules.dom?.forEach((rule, i) => {
      const id = domQueryId(sig.id, i);
      if (rule.keyPrefix) domProperties.push({ id, selector: rule.selector, keyPrefix: rule.keyPrefix });
      else dom.push({ id, selector: rule.selector, attribute: rule.attribute, text: rule.text });
    });
  }
  return { globals: [...globals].sort(), dom, domProperties };
}

interface Candidate {
  value: string;
  key?: string;
  isUrl?: boolean;
}

interface Hit {
  type: EvidenceType;
  key?: string;
  raw: string;
  value: string;
  version?: string;
  confidence: number;
}

function applyVersionTemplate(template: string | undefined, match: RegExpExecArray): string | undefined {
  if (!template) return undefined;
  // Conditional form "$1?a:b": "a" when group 1 captured something, otherwise "b".
  const ternary = /^\$(\d)\?([^:]*):(.*)$/.exec(template);
  if (ternary) template = match[Number(ternary[1])] ? ternary[2]! : ternary[3]!;
  if (!template) return undefined;
  const filled = template.replace(/\$(\d)/g, (_, n: string) => match[Number(n)] ?? '');
  // A template whose capture group was empty (e.g. "0.$1" with no match) yields no version.
  if (/\$\d/.test(template) && template.replace(/\$\d/g, '') === filled) return undefined;
  return normalizeVersion(filled) ?? undefined;
}

function excerpt(candidate: Candidate, match: RegExpExecArray): string {
  const text = candidate.isUrl ? redactUrl(candidate.value) : redactTokens(match[0] || candidate.value);
  return sanitizeText(text, EVIDENCE_MAX_LENGTH);
}

function testRules(type: EvidenceType, rules: Rule[] | undefined, candidates: Candidate[], hits: Hit[][]): void {
  if (!rules) return;
  for (const rule of rules) {
    const ruleHits: Hit[] = [];
    for (const c of candidates) {
      const m = rule.pattern.exec(c.value);
      if (!m) continue;
      ruleHits.push({
        type,
        key: c.key,
        raw: c.value,
        value: excerpt(c, m),
        version: applyVersionTemplate(rule.version, m),
        confidence: rule.confidence,
      });
      if (ruleHits.length >= MAX_EVIDENCE_PER_RULE && !rule.version) break;
    }
    if (ruleHits.length) hits.push(ruleHits);
  }
}

const DISTRO = /\b(ubuntu|debian|centos|red ?hat|rhel|el[6-9]|fedora|suse|amzn|amazon linux|alpine|deb\d+u\d+)\b/i;

/** Candidate lists shared by every signature for one snapshot (built once, not per signature). */
interface PageCandidates {
  html: Candidate[];
  script: Candidate[];
  scriptSrc: Candidate[];
  stylesheet: Candidate[];
  url: Candidate[];
  resource: Candidate[];
}

function matchSignature(sig: Signature, page: PageSnapshot, c: PageCandidates): Hit[][] {
  const hits: Hit[][] = [];
  const { rules } = sig;

  testRules('html', rules.html, c.html, hits);
  testRules('script', rules.script, c.script, hits);
  testRules('scriptSrc', rules.scriptSrc, c.scriptSrc, hits);
  testRules('stylesheet', rules.stylesheet, c.stylesheet, hits);
  testRules('url', rules.url, c.url, hits);
  testRules('resource', rules.resource, c.resource, hits);

  for (const [name, list] of Object.entries(rules.meta ?? {})) {
    const values = page.meta[name] ?? [];
    testRules('meta', list, values.map((value) => ({ value, key: name })), hits);
  }
  if (page.headers) {
    for (const [name, list] of Object.entries(rules.headers ?? {})) {
      const value = page.headers[name];
      if (value !== undefined) testRules('header', list, [{ value, key: name }], hits);
    }
  }
  for (const [path, list] of Object.entries(rules.globals ?? {})) {
    const value = page.globals[path];
    if (value !== undefined) testRules('global', list, [{ value, key: path }], hits);
  }
  for (const rule of rules.cookies ?? []) {
    const names = page.cookieNames.filter((n) => rule.name.test(n)).slice(0, MAX_EVIDENCE_PER_RULE);
    if (names.length) {
      hits.push(names.map((n) => ({ type: 'cookie' as const, key: n, raw: n, value: sanitizeText(n, 80), confidence: rule.confidence })));
    }
  }
  rules.dom?.forEach((domRule, i) => {
    const result = page.dom[domQueryId(sig.id, i)];
    if (!result || result.count === 0) return;
    const candidates: Candidate[] =
      domRule.attribute || domRule.text
        ? result.values.map((value) => ({ value, key: domRule.selector }))
        : [{ value: '', key: domRule.selector }];
    const before = hits.length;
    testRules('dom', [domRule.rule], candidates, hits);
    // Presence-only DOM rules have no text to excerpt: describe what was found instead.
    for (const group of hits.slice(before)) {
      for (const h of group) {
        if (!h.value) {
          h.value = domRule.keyPrefix
            ? `${result.count} elemento(s) com propriedade ${domRule.keyPrefix}…`
            : `${result.count} elemento(s) ${domRule.selector}`;
        }
      }
    }
  });
  return hits;
}

function confidenceLevel(confidence: number): ConfidenceLevel {
  if (confidence >= 80) return 'high';
  if (confidence >= 50) return 'medium';
  return 'low';
}

function buildDetection(sig: Signature, hits: Hit[][]): Detection | null {
  // Each rule counts once, at its own confidence; version-only rules (0) never detect.
  const confidence = Math.min(100, hits.reduce((sum, group) => sum + Math.max(...group.map((h) => h.confidence)), 0));
  if (confidence <= 0) return null;

  const flat = hits.flat();
  const evidence: Evidence[] = flat.map((h) => ({
    type: h.type,
    key: h.key,
    value: h.value,
    version: h.version,
    confidence: h.confidence,
    observed: true,
  }));

  // The runtime value of a global is what is actually executing; generator/banners come next; file names last.
  const typeBonus = (t: EvidenceType) => (t === 'global' ? 10 : t === 'meta' || t === 'header' || t === 'dom' ? 5 : 0);
  const candidates = flat
    .filter((h) => h.version)
    .map((h) => ({ version: h.version!, weight: Math.max(h.confidence, 25) + typeBonus(h.type) }));
  const { version, conflicts } = mergeVersionCandidates(candidates);

  const notes: string[] = [];
  if (sig.note) notes.push(sig.note);
  if (conflicts.length && version) {
    notes.push(
      `Múltiplas versões observadas (${[version, ...conflicts].join(', ')}). A correlação de CVEs exige uma versão inequívoca.`,
    );
  }
  let distroPackage: string | undefined;
  const versionHit = flat.find((h) => h.type === 'header' && h.version === version);
  const distro = versionHit ? DISTRO.exec(versionHit.raw) : null;
  if (distro) {
    distroPackage = distro[1];
    notes.push(
      `O banner indica um pacote de distribuição (${distro[1]}): correções podem ter sido aplicadas por backport sem alterar o número da versão.`,
    );
  }

  return {
    id: sig.id,
    name: sig.name,
    categories: sig.categories,
    website: sig.website,
    confidence,
    confidenceLevel: confidenceLevel(confidence),
    version,
    versionExact: Boolean(version && isExactVersion(version) && conflicts.length === 0),
    versionConflicts: conflicts,
    inferred: false,
    evidence,
    notes,
    distroPackage,
    cpe: sig.cpe,
    npm: sig.npm,
    source: sig.source,
  };
}

function evidenceKey(e: Evidence): string {
  return `${e.type}:${e.key ?? ''}`;
}

function sortDetections(list: Detection[]): Detection[] {
  const rank = (d: Detection) => Math.min(...d.categories.map((c) => CATEGORY_ORDER.indexOf(c)).filter((i) => i >= 0), 999);
  return list.sort((a, b) => rank(a) - rank(b) || Number(a.inferred) - Number(b.inferred) || a.name.localeCompare(b.name));
}

/** Runs every signature against the snapshot. Pure and deterministic. */
export function detectTechnologies(page: PageSnapshot, signatures: Signature[] = SIGNATURES): Detection[] {
  const byId = new Map(signatures.map((s) => [s.id, s]));

  const scriptUrls = unique([
    ...page.scriptSrcs,
    ...page.resources.filter((r) => r.initiatorType === 'script').map((r) => r.url),
  ]);
  const styleUrls = unique([
    ...page.stylesheets,
    ...page.resources.filter((r) => r.initiatorType === 'link' || r.initiatorType === 'css').map((r) => r.url).filter((u) => /\.css(?:[?#]|$)|\/css2?\?|fonts\.googleapis/.test(u)),
  ]);
  const urls = (list: string[]): Candidate[] => list.map((value) => ({ value, isUrl: true }));
  const candidates: PageCandidates = {
    html: page.html ? [{ value: page.html }] : [],
    script: page.inlineScripts ? [{ value: page.inlineScripts }] : [],
    scriptSrc: urls(scriptUrls),
    stylesheet: urls(styleUrls),
    url: urls([page.url]),
    resource: urls(page.resources.map((r) => r.url)),
  };

  const detected = new Map<string, Detection>();
  for (const sig of signatures) {
    const hits = matchSignature(sig, page, candidates);
    if (!hits.length) continue;
    const det = buildDetection(sig, hits);
    if (det) detected.set(sig.id, det);
  }

  // Exclusions: drop B when everything that pointed to B is also evidence for A (e.g. Lodash vs Underscore `_.VERSION`).
  for (const det of [...detected.values()]) {
    for (const exId of byId.get(det.id)?.excludes ?? []) {
      const other = detected.get(exId);
      if (!other) continue;
      const own = new Set(det.evidence.map(evidenceKey));
      if (other.evidence.every((e) => own.has(evidenceKey(e)))) detected.delete(exId);
    }
  }

  // Requirements: a technology that only makes sense on top of another (a WordPress plugin, a
  // Shopify app) is dropped when nothing it requires is present. Repeated until stable, since
  // dropping one detection can leave another without its requirement.
  for (let changed = true; changed; ) {
    changed = false;
    const present = withImplied(detected.keys(), byId);
    const presentCategories = new Set([...present].flatMap((id) => byId.get(id)?.categories ?? []));
    for (const det of [...detected.values()]) {
      const sig = byId.get(det.id)!;
      const missingTech = sig.requires?.length && !sig.requires.some((id) => present.has(id));
      const missingCategory = sig.requiresCategories?.length && !sig.requiresCategories.some((c) => presentCategories.has(c));
      if (missingTech || missingCategory) {
        detected.delete(det.id);
        changed = true;
      }
    }
  }

  // Implications are inferences: no version, explicitly marked as not observed.
  const queue = [...detected.values()];
  while (queue.length) {
    const parent = queue.shift()!;
    for (const childId of byId.get(parent.id)?.implies ?? []) {
      const childSig = byId.get(childId);
      if (!childSig) continue;
      const existing = detected.get(childId);
      if (existing) {
        if (!existing.impliedBy?.includes(parent.name)) existing.impliedBy = [...(existing.impliedBy ?? []), parent.name];
        continue;
      }
      const confidence = Math.max(25, Math.round(parent.confidence * 0.75));
      const child: Detection = {
        id: childSig.id,
        name: childSig.name,
        categories: childSig.categories,
        website: childSig.website,
        confidence,
        confidenceLevel: confidenceLevel(confidence),
        versionExact: false,
        versionConflicts: [],
        inferred: true,
        impliedBy: [parent.name],
        evidence: [
          {
            type: 'implied',
            key: parent.id,
            value: `Inferido a partir de ${parent.name}`,
            confidence,
            observed: false,
          },
        ],
        notes: childSig.note ? [childSig.note] : [],
        cpe: childSig.cpe,
        npm: childSig.npm,
        source: childSig.source,
      };
      detected.set(childId, child);
      queue.push(child);
    }
  }

  return sortDetections([...detected.values()]);
}

function unique(list: string[]): string[] {
  return [...new Set(list)];
}

/** The given ids plus everything they transitively imply. */
function withImplied(ids: Iterable<string>, byId: Map<string, Signature>): Set<string> {
  const present = new Set(ids);
  const queue = [...present];
  while (queue.length) {
    for (const child of byId.get(queue.shift()!)?.implies ?? []) {
      if (byId.has(child) && !present.has(child)) {
        present.add(child);
        queue.push(child);
      }
    }
  }
  return present;
}
