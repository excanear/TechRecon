// Converts the community Wappalyzer dataset (enthec/webappanalyzer) into TechRecon signatures.
// Pure: the raw JSON comes in, Signature[] comes out. The data is untrusted (downloaded at
// runtime), so every field is shape-checked and every pattern compiled defensively; anything
// malformed is skipped and counted, never guessed.
//
// Precedence: the hand-curated signatures win. A Wappalyzer entry for a technology that is
// already curated is dropped entirely (its references are redirected to the curated id), so a
// curated detection is never diluted by community rules.

import type { CategoryId } from '../../types';
import type { CookieRule, DomRule, Rule, Signature, SignatureRules } from '../signature';

type RawPatterns = string | string[];

interface RawDomSpec {
  exists?: string;
  text?: string;
  attributes?: Record<string, string>;
  properties?: Record<string, string>;
}

export interface RawTechnology {
  cats?: number[];
  website?: string;
  cpe?: string;
  implies?: RawPatterns;
  excludes?: RawPatterns;
  requires?: RawPatterns;
  requiresCategory?: number | number[];
  html?: RawPatterns;
  scriptSrc?: RawPatterns;
  scripts?: RawPatterns;
  url?: RawPatterns;
  xhr?: RawPatterns;
  meta?: Record<string, RawPatterns>;
  headers?: Record<string, RawPatterns>;
  cookies?: Record<string, RawPatterns>;
  js?: Record<string, RawPatterns>;
  dom?: RawPatterns | Record<string, RawDomSpec>;
}

export interface RawCategory {
  name: string;
}

/**
 * Community rules count for less than curated ones: each rule contributes 80% of its stated
 * confidence, so a single weak Wappalyzer hint lands lower than the same hint from a curated rule.
 */
export const WAPPALYZER_CONFIDENCE_WEIGHT = 0.8;

/** Pattern length guard: an absurdly long regex from a corrupted dataset is not run on 1 MB of HTML. */
const MAX_PATTERN_LENGTH = 2000;

/** Wappalyzer names of technologies that are curated here under another name. Verified by website. */
export const CURATED_ALIASES: Record<string, string> = {
  'TYPO3 CMS': 'typo3',
  'HubSpot CMS Hub': 'hubspot-cms',
  'Nuxt.js': 'nuxt',
  Polyfill: 'polyfill-io',
  'Microsoft ASP.NET': 'aspnet',
  Bunny: 'bunnycdn',
  'Adobe Experience Platform Launch': 'adobe-launch',
  'Matomo Analytics': 'matomo',
  'Cloudflare Browser Insights': 'cloudflare-web-analytics',
  Datadog: 'datadog-rum',
  'Google Font API': 'google-fonts',
};

/** Wappalyzer category id → TechRecon category. Unlisted ids map to "other". */
const CATEGORY_MAP: Record<number, CategoryId> = {
  1: 'cms', 2: 'cms', 4: 'cms', 8: 'cms', 11: 'cms', 21: 'cms', 50: 'cms', 51: 'cms',
  80: 'cms-extension', 81: 'cms-extension', 82: 'cms-extension', 87: 'cms-extension', 100: 'cms-extension',
  6: 'ecommerce', 98: 'ecommerce', 106: 'ecommerce', 108: 'ecommerce',
  41: 'payment', 91: 'payment',
  10: 'analytics', 74: 'analytics', 83: 'analytics', 86: 'analytics', 97: 'analytics',
  42: 'tag-manager',
  31: 'cdn',
  16: 'security', 69: 'security', 70: 'security',
  22: 'web-server', 33: 'web-server', 64: 'web-server', 65: 'web-server',
  27: 'language',
  18: 'web-framework',
  12: 'js-framework', 26: 'js-framework',
  59: 'js-library', 24: 'js-library', 25: 'js-library',
  66: 'ui-framework',
  9: 'paas', 60: 'paas', 62: 'paas', 63: 'paas', 88: 'paas',
  57: 'ssg',
  17: 'font',
  5: 'widget', 14: 'widget', 15: 'widget', 35: 'widget', 52: 'widget', 58: 'widget', 68: 'widget',
  72: 'widget', 73: 'widget', 89: 'widget', 90: 'widget', 110: 'widget',
  78: 'monitoring', 92: 'monitoring',
  44: 'build-tool', 47: 'build-tool',
  23: 'cache',
  67: 'consent',
  3: 'database', 34: 'database',
  28: 'os',
  32: 'marketing', 36: 'marketing', 53: 'marketing', 54: 'marketing', 71: 'marketing', 75: 'marketing',
  76: 'marketing', 77: 'marketing', 84: 'marketing', 94: 'marketing',
};

export interface ConversionStats {
  /** Technologies in the dataset. */
  technologies: number;
  /** Signatures produced (excludes the curated overlap). */
  signatures: number;
  /** Dataset entries dropped because a curated signature covers them. */
  curatedOverlap: number;
  /** Signatures with no rule usable in a browser (DNS/TLS/robots only): they can only be inferred. */
  inferOnly: number;
  /** Detection rules produced. */
  rules: number;
  /** Patterns that failed to compile or were malformed. */
  invalidPatterns: number;
}

export interface ConversionResult {
  signatures: Signature[];
  stats: ConversionStats;
}

interface ParsedPattern {
  pattern: RegExp;
  version?: string;
  confidence: number;
}

function asList(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'tech';
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Parses "regex\;version:\1\;confidence:50". Wappalyzer version templates use "\1" (and the
 * conditional "\1?a:b"); TechRecon templates use "$1", so the back-references are rewritten.
 */
export function parsePattern(raw: string): ParsedPattern | null {
  const [source = '', ...tags] = raw.split('\\;');
  if (source.length > MAX_PATTERN_LENGTH) return null;
  let pattern: RegExp;
  try {
    pattern = new RegExp(source, 'i');
  } catch {
    return null;
  }
  let version: string | undefined;
  let confidence = 100;
  for (const tag of tags) {
    const colon = tag.indexOf(':');
    if (colon < 0) continue;
    const key = tag.slice(0, colon);
    const value = tag.slice(colon + 1);
    if (key === 'version') version = value.replace(/\\(\d)/g, '$$$1') || undefined;
    else if (key === 'confidence') {
      const n = Number(value);
      if (Number.isFinite(n)) confidence = Math.min(100, Math.max(0, n));
    }
  }
  return { pattern, version, confidence };
}

/** Strips "\;confidence:…" style suffixes from a technology reference (implies/excludes/requires). */
function refName(raw: string): string {
  return raw.split('\\;')[0]!.trim();
}

/**
 * Wappalyzer cookie keys are mostly literal names, sometimes with a trailing "*" wildcard, a
 * leading "(?i)" or a regex. Only names are readable from the page, so value patterns are not
 * checked; the name match is anchored on both ends.
 */
export function cookieNamePattern(key: string): RegExp | null {
  let name = key.trim();
  let flags = '';
  if (name.startsWith('(?i)')) {
    name = name.slice(4);
    flags = 'i';
  }
  if (!name) return null;
  if (name.endsWith('*')) return new RegExp(`^${escapeRegExp(name.slice(0, -1))}`, flags);
  const literal = escapeRegExp(name);
  try {
    return new RegExp(`^(?:${literal}|${name})$`, flags);
  } catch {
    return new RegExp(`^${literal}$`, flags);
  }
}

function cpePairs(raw: unknown): string[] | undefined {
  if (typeof raw !== 'string') return undefined;
  const parts = raw.split(':');
  // cpe:2.3:a:vendor:product:… — only applications ("a") are correlated.
  if (parts[0] !== 'cpe' || parts[2] !== 'a' || !parts[3] || !parts[4] || parts[3] === '*' || parts[4] === '*') return undefined;
  return [`${parts[3]}:${parts[4]}`];
}

function mapCategories(raw: unknown): CategoryId[] {
  const ids = Array.isArray(raw) ? raw : typeof raw === 'number' ? [raw] : [];
  const mapped = ids.filter((n): n is number => typeof n === 'number').map((n) => CATEGORY_MAP[n] ?? 'other');
  const unique = [...new Set(mapped)];
  // "other" only when nothing more specific applies.
  const specific = unique.filter((c) => c !== 'other');
  return specific.length ? specific : ['other'];
}

class RuleBuilder {
  rules = 0;
  invalid = 0;

  rule(raw: string): Rule | null {
    const parsed = parsePattern(raw);
    if (!parsed) {
      this.invalid++;
      return null;
    }
    this.rules++;
    return {
      pattern: parsed.pattern,
      version: parsed.version,
      confidence: Math.round(parsed.confidence * WAPPALYZER_CONFIDENCE_WEIGHT),
    };
  }

  list(raw: unknown): Rule[] | undefined {
    const out = asList(raw).map((p) => this.rule(p)).filter((r): r is Rule => r !== null);
    return out.length ? out : undefined;
  }

  keyed(raw: unknown, normalizeKey: (k: string) => string): Record<string, Rule[]> | undefined {
    if (!isRecord(raw)) return undefined;
    const out: Record<string, Rule[]> = {};
    for (const [key, value] of Object.entries(raw)) {
      const k = normalizeKey(key);
      const rules = this.list(value);
      if (k && rules) (out[k] ??= []).push(...rules);
    }
    return Object.keys(out).length ? out : undefined;
  }

  cookies(raw: unknown): CookieRule[] | undefined {
    if (!isRecord(raw)) return undefined;
    const out: CookieRule[] = [];
    for (const [key, value] of Object.entries(raw)) {
      const name = cookieNamePattern(key);
      const rule = this.rule(asList(value)[0] ?? '');
      if (!name || !rule) continue;
      out.push({ name, confidence: rule.confidence });
    }
    return out.length ? out : undefined;
  }

  dom(raw: unknown): DomRule[] | undefined {
    const out: DomRule[] = [];
    const presence = (selector: string) => {
      const rule = this.rule('');
      if (rule) out.push({ selector, rule });
    };
    if (typeof raw === 'string' || Array.isArray(raw)) {
      for (const selector of asList(raw)) presence(selector);
    } else if (isRecord(raw)) {
      for (const [selector, spec] of Object.entries(raw)) {
        if (!isRecord(spec)) continue;
        const { exists, text, attributes, properties } = spec as RawDomSpec;
        let added = false;
        if (typeof text === 'string') {
          const rule = this.rule(text);
          if (rule) out.push({ selector, text: true, rule });
          added = true;
        }
        if (isRecord(attributes)) {
          for (const [attribute, pattern] of Object.entries(attributes)) {
            if (typeof pattern !== 'string') continue;
            const rule = this.rule(pattern);
            if (rule) out.push({ selector, attribute, rule });
            added = true;
          }
        }
        if (isRecord(properties)) {
          // Element properties are probed by key only; their values are never read from the page.
          for (const [property, pattern] of Object.entries(properties)) {
            if (typeof pattern !== 'string') continue;
            const rule = this.rule(pattern);
            if (rule) out.push({ selector, keyPrefix: property, rule: { pattern: /[\s\S]*/, confidence: rule.confidence } });
            added = true;
          }
        }
        if (typeof exists === 'string' || !added) presence(selector);
      }
    }
    return out.length ? out : undefined;
  }
}

/** Converts the raw dataset. `curated` decides precedence and the ids references resolve to. */
export function convertWappalyzer(
  technologies: Record<string, RawTechnology>,
  curated: Signature[],
): ConversionResult {
  const curatedById = new Set(curated.map((s) => s.id));
  const curatedByName = new Map<string, string>();
  for (const s of curated) {
    curatedByName.set(normalizeName(s.name), s.id);
    curatedByName.set(normalizeName(s.id), s.id);
  }
  const curatedIdFor = (name: string): string | undefined => {
    const alias = CURATED_ALIASES[name];
    if (alias && curatedById.has(alias)) return alias;
    return curatedByName.get(normalizeName(name));
  };

  // Resolve every dataset name to its final id first, so references can point forward.
  const names = Object.keys(technologies).sort((a, b) => a.localeCompare(b));
  const idFor = new Map<string, string>();
  const taken = new Set(curatedById);
  for (const name of names) {
    const curatedId = curatedIdFor(name);
    if (curatedId) {
      idFor.set(name, curatedId);
      continue;
    }
    let id = `wa-${slug(name)}`;
    for (let n = 2; taken.has(id); n++) id = `wa-${slug(name)}-${n}`;
    taken.add(id);
    idFor.set(name, id);
  }
  const refs = (raw: unknown): string[] | undefined => {
    const ids = asList(raw)
      .map(refName)
      .map((n) => idFor.get(n))
      .filter((id): id is string => Boolean(id));
    return ids.length ? [...new Set(ids)] : undefined;
  };

  const builder = new RuleBuilder();
  const signatures: Signature[] = [];
  let curatedOverlap = 0;
  let inferOnly = 0;

  for (const name of names) {
    const tech = technologies[name];
    if (!isRecord(tech)) continue;
    const id = idFor.get(name)!;
    if (curatedById.has(id)) {
      curatedOverlap++;
      continue;
    }

    const rules: SignatureRules = {
      html: builder.list(tech.html),
      scriptSrc: builder.list(tech.scriptSrc),
      script: builder.list(tech.scripts),
      url: builder.list(tech.url),
      resource: builder.list(tech.xhr),
      meta: builder.keyed(tech.meta, (k) => k.trim().toLowerCase()),
      headers: builder.keyed(tech.headers, (k) => k.trim().toLowerCase()),
      globals: builder.keyed(tech.js, (k) => k.trim()),
      cookies: builder.cookies(tech.cookies),
      dom: builder.dom(tech.dom),
    };
    for (const key of Object.keys(rules) as Array<keyof SignatureRules>) if (rules[key] === undefined) delete rules[key];
    if (!Object.keys(rules).length) inferOnly++;

    const signature: Signature = {
      id,
      name,
      categories: mapCategories(tech.cats),
      source: 'wappalyzer',
      rules,
    };
    if (typeof tech.website === 'string' && /^https?:\/\//.test(tech.website)) signature.website = tech.website;
    const cpe = cpePairs(tech.cpe);
    if (cpe) signature.cpe = cpe;
    const implies = refs(tech.implies)?.filter((r) => r !== id);
    if (implies?.length) signature.implies = implies;
    const excludes = refs(tech.excludes)?.filter((r) => r !== id);
    if (excludes?.length) signature.excludes = excludes;
    const requires = refs(tech.requires);
    if (requires) signature.requires = requires;
    if (tech.requiresCategory !== undefined) signature.requiresCategories = mapCategories(tech.requiresCategory);
    signatures.push(signature);
  }

  return {
    signatures,
    stats: {
      technologies: names.length,
      signatures: signatures.length,
      curatedOverlap,
      inferOnly,
      rules: builder.rules,
      invalidPatterns: builder.invalid,
    },
  };
}
