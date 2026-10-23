import { safeHttpUrl, safeIdentifier, sanitizeMultiline, sanitizeText } from '../shared/sanitize';
import type { CvssInfo, Reference, Vulnerability } from '../types';
import { cvss3BaseScore, normalizeSeverity, severityFromScore } from './cvss';
import { requestJson, type FetchLike, type Sleep, type Throttle } from './http';
import { compareVersions } from './version';

export const OSV_ENDPOINT = 'https://api.osv.dev/v1/query';
const MAX_PAGES = 5;

// ───────── Raw API shapes (subset of the OSV schema) ─────────

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
  versions?: string[];
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  modified?: string;
  withdrawn?: string;
  severity?: Array<{ type?: string; score?: string }>;
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url?: string }>;
  database_specific?: { severity?: string };
}

export interface OsvResponse {
  vulns?: OsvVuln[];
  next_page_token?: string;
}

// ───────── Range evaluation ─────────

export interface OsvRangeMatch {
  matched: boolean;
  ranges: string[];
  fixedIn?: string;
}

/**
 * Evaluates OSV SEMVER/ECOSYSTEM events for `version`, restricted to the affected entries of
 * the exact package (an advisory may also list e.g. Drupal or NuGet packages with other ranges).
 */
export function evaluateOsvAffected(
  affected: OsvAffected[] | undefined,
  ecosystem: string,
  packageName: string,
  version: string,
): OsvRangeMatch {
  const ranges = new Set<string>();
  const fixes: string[] = [];
  for (const entry of affected ?? []) {
    if (entry.package?.ecosystem !== ecosystem || entry.package?.name !== packageName) continue;

    if (entry.versions?.some((v) => compareVersions(v, version) === 0)) ranges.add(`= ${version} (lista explícita)`);

    for (const range of entry.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      let introduced: string | null = null;
      for (const ev of range.events ?? []) {
        if (ev.introduced !== undefined) {
          introduced = ev.introduced;
          continue;
        }
        if (introduced === null) continue;
        const end = ev.fixed ?? ev.last_affected ?? ev.limit;
        if (end === undefined) continue;
        if (inInterval(version, introduced, end, ev.last_affected !== undefined)) {
          ranges.add(describeInterval(introduced, end, ev.last_affected !== undefined));
          if (ev.fixed) fixes.push(ev.fixed);
        }
        introduced = null;
      }
      // An open interval: introduced with no end event means every later version is affected.
      if (introduced !== null && inInterval(version, introduced, undefined, false)) {
        ranges.add(describeInterval(introduced, undefined, false));
      }
    }
  }
  const fixedIn = fixes.sort((a, b) => compareVersions(a, b) ?? 0)[0];
  return { matched: ranges.size > 0, ranges: [...ranges], fixedIn };
}

function inInterval(version: string, introduced: string, end: string | undefined, inclusiveEnd: boolean): boolean {
  if (introduced !== '0') {
    const c = compareVersions(version, introduced);
    if (c === null || c < 0) return false;
  }
  if (end === undefined) return true;
  const c = compareVersions(version, end);
  if (c === null) return false;
  return inclusiveEnd ? c <= 0 : c < 0;
}

function describeInterval(introduced: string, end: string | undefined, inclusiveEnd: boolean): string {
  const parts: string[] = [];
  if (introduced !== '0') parts.push(`>= ${introduced}`);
  if (end !== undefined) parts.push(`${inclusiveEnd ? '<=' : '<'} ${end}`);
  return parts.length ? parts.join(', ') : 'todas as versões';
}

// ───────── Normalization ─────────

function osvCvss(vuln: OsvVuln): CvssInfo | null {
  const declared = normalizeSeverity(vuln.database_specific?.severity);
  const v3 = vuln.severity?.find((s) => s.type === 'CVSS_V3' && typeof s.score === 'string');
  if (v3?.score) {
    const score = cvss3BaseScore(v3.score);
    return {
      version: v3.score.startsWith('CVSS:3.0') ? '3.0' : '3.1',
      score,
      vector: sanitizeText(v3.score, 200),
      severity: score !== null ? severityFromScore(score) : declared,
    };
  }
  const v4 = vuln.severity?.find((s) => s.type === 'CVSS_V4' && typeof s.score === 'string');
  if (v4?.score) {
    // CVSS v4 scoring needs the full lookup tables; show the vector and the advisory's own severity.
    return { version: '4.0', score: null, vector: sanitizeText(v4.score, 200), severity: declared };
  }
  return declared !== 'UNKNOWN' ? { version: '-', score: null, vector: '', severity: declared } : null;
}

function osvReferences(vuln: OsvVuln, id: string): Reference[] {
  const out: Reference[] = [];
  const seen = new Set<string>();
  const add = (raw: string | undefined, label: string) => {
    const url = safeHttpUrl(raw);
    if (!url || seen.has(url) || out.length >= 10) return;
    seen.add(url);
    out.push({ url, label });
  };
  if (id.startsWith('GHSA-')) add(`https://github.com/advisories/${id}`, 'GitHub Advisory');
  for (const ref of vuln.references ?? []) {
    add(ref.url, sanitizeText(ref.type ?? '', 20) || 'WEB');
  }
  return out;
}

export interface OsvNormalizeResult {
  vulns: Vulnerability[];
  discarded: number;
}

export function normalizeOsvResponse(
  responses: OsvResponse[],
  ecosystem: string,
  packageName: string,
  version: string,
): OsvNormalizeResult {
  const vulns: Vulnerability[] = [];
  let discarded = 0;
  for (const response of responses) {
    for (const vuln of response.vulns ?? []) {
      const advisoryId = safeIdentifier(vuln?.id);
      if (!advisoryId || vuln.withdrawn) continue;
      const match = evaluateOsvAffected(vuln.affected, ecosystem, packageName, version);
      if (!match.matched) {
        discarded++;
        continue;
      }
      const aliases = (vuln.aliases ?? []).map(safeIdentifier).filter((a): a is string => a !== null);
      const cve = aliases.find((a) => /^CVE-\d{4}-\d{4,}$/.test(a));
      const id = cve ?? advisoryId;
      const cvss = osvCvss(vuln);
      const description = sanitizeMultiline(vuln.details ?? '', 2000);
      vulns.push({
        id,
        aliases: [advisoryId, ...aliases].filter((a) => a !== id).filter((a, i, arr) => arr.indexOf(a) === i),
        title: sanitizeText(vuln.summary ?? '', 160) || id,
        description,
        cvss,
        severity: cvss?.severity ?? 'UNKNOWN',
        published: sanitizeText(vuln.published ?? '', 40) || undefined,
        modified: sanitizeText(vuln.modified ?? '', 40) || undefined,
        affected: match.ranges,
        fixedIn: match.fixedIn,
        matchBasis: `Versão ${version} dentro de ${match.ranges.join(' | ')} (${ecosystem}/${packageName})`,
        source: 'osv',
        sourceUrl: `https://osv.dev/vulnerability/${advisoryId}`,
        references: osvReferences(vuln, advisoryId),
      });
    }
  }
  return { vulns, discarded };
}

// ───────── Client ─────────

export interface OsvClientOptions {
  fetch: FetchLike;
  throttle?: Throttle;
  sleep?: Sleep;
}

export async function fetchOsv(ecosystem: string, packageName: string, version: string, opts: OsvClientOptions): Promise<OsvResponse[]> {
  const pages: OsvResponse[] = [];
  let pageToken: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const body: Record<string, unknown> = { version, package: { name: packageName, ecosystem } };
    if (pageToken) body.page_token = pageToken;
    const page = await requestJson<OsvResponse>(
      OSV_ENDPOINT,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
      { fetch: opts.fetch, throttle: opts.throttle, sleep: opts.sleep, label: 'OSV', timeoutMs: 30000, retries: 1, retryDelayMs: 3000 },
    );
    if (!page || typeof page !== 'object') throw new Error('OSV: formato de resposta inesperado.');
    pages.push(page);
    pageToken = typeof page.next_page_token === 'string' && page.next_page_token ? page.next_page_token : undefined;
    if (!pageToken) break;
  }
  return pages;
}
