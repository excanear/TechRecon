import { safeHttpUrl, safeIdentifier, sanitizeMultiline, sanitizeText } from '../shared/sanitize';
import type { CvssInfo, Reference, Severity, Vulnerability } from '../types';
import { buildMatchString, evaluateNvdConfigurations, type NvdConfiguration } from './cpe';
import { normalizeSeverity, severityFromScore } from './cvss';
import { requestJson, type FetchLike, type Sleep, type Throttle } from './http';

export const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 2000;
const MAX_RESULTS = 4000;

// ───────── Raw API shapes (subset) ─────────

interface NvdCvssData {
  version?: string;
  vectorString?: string;
  baseScore?: number;
  baseSeverity?: string;
}

interface NvdMetric {
  source?: string;
  type?: 'Primary' | 'Secondary';
  cvssData?: NvdCvssData;
  baseSeverity?: string;
}

export interface NvdCve {
  id: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: Array<{ lang: string; value: string }>;
  metrics?: Record<string, NvdMetric[] | undefined>;
  configurations?: NvdConfiguration[];
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
}

export interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities?: Array<{ cve: NvdCve }>;
}

// ───────── Normalization ─────────

const METRIC_ORDER: Array<[string, string]> = [
  ['cvssMetricV40', '4.0'],
  ['cvssMetricV31', '3.1'],
  ['cvssMetricV30', '3.0'],
  ['cvssMetricV2', '2.0'],
];

export function pickCvss(metrics: NvdCve['metrics']): CvssInfo | null {
  if (!metrics) return null;
  const options: Array<{ metric: NvdMetric; version: string }> = [];
  for (const [key, version] of METRIC_ORDER) {
    for (const metric of metrics[key] ?? []) options.push({ metric, version });
  }
  // Prefer NVD's own (Primary) assessment, newest CVSS version first; otherwise the first CNA score.
  const chosen = options.find((o) => o.metric.type === 'Primary') ?? options[0];
  if (!chosen?.metric.cvssData) return null;
  const data = chosen.metric.cvssData;
  const score = typeof data.baseScore === 'number' && Number.isFinite(data.baseScore) ? data.baseScore : null;
  const declared = normalizeSeverity(data.baseSeverity ?? chosen.metric.baseSeverity);
  const severity: Severity = declared !== 'UNKNOWN' ? declared : severityFromScore(score);
  return {
    version: data.version ?? chosen.version,
    score,
    vector: sanitizeText(data.vectorString ?? '', 200),
    severity,
    source: sanitizeText(chosen.metric.source ?? '', 80) || undefined,
  };
}

function englishDescription(cve: NvdCve): string {
  const d = cve.descriptions?.find((x) => x.lang === 'en') ?? cve.descriptions?.[0];
  return sanitizeMultiline(d?.value ?? '', 2000);
}

const PRODUCT_INTRO =
  /^[^.]{0,80}\b(?:is|are) (?:an?|the) [^.]{0,100}\b(?:platform|library|framework|software|application|system|server|tool|project|plugin|module|package|engine|CMS|content management)\b/i;

/**
 * NVD has no titles: use the first sentence of the description, skipping the product
 * introduction many CNAs start with ("WordPress is an open publishing platform for the Web.").
 */
export function titleFromDescription(description: string): string {
  const sentences = description.match(/.{20,}?[.!?](?=\s|$)|.+$/gs)?.map((s) => s.trim()).filter(Boolean) ?? [];
  const first = sentences[0] ?? description;
  const chosen = PRODUCT_INTRO.test(first) && sentences[1] ? sentences[1] : first;
  return sanitizeText(chosen, 140);
}

function references(cve: NvdCve): Reference[] {
  const out: Reference[] = [];
  const seen = new Set<string>();
  for (const ref of cve.references ?? []) {
    const url = safeHttpUrl(ref.url);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    const tags = (ref.tags ?? []).map((t) => sanitizeText(t, 40)).filter(Boolean);
    out.push({ url, label: tags.length ? tags.slice(0, 2).join(', ') : new URL(url).hostname });
    if (out.length >= 10) break;
  }
  return out;
}

export interface NvdNormalizeResult {
  vulns: Vulnerability[];
  /** Returned by NVD but not confirmed by local range evaluation. */
  discarded: number;
}

export function normalizeNvdResponse(
  responses: NvdResponse[],
  vendorProducts: string[],
  version: string,
): NvdNormalizeResult {
  const vulns: Vulnerability[] = [];
  let discarded = 0;
  for (const response of responses) {
    for (const item of response.vulnerabilities ?? []) {
      const cve = item.cve;
      const id = safeIdentifier(cve?.id);
      if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id)) continue;
      if (cve.vulnStatus === 'Rejected') continue;

      const match = evaluateNvdConfigurations(cve.configurations, vendorProducts, version);
      if (!match.matched) {
        discarded++;
        continue;
      }
      const cvss = pickCvss(cve.metrics);
      const description = englishDescription(cve);
      vulns.push({
        id,
        aliases: [],
        title: titleFromDescription(description) || id,
        description,
        cvss,
        severity: cvss?.severity ?? 'UNKNOWN',
        published: sanitizeText(cve.published ?? '', 40) || undefined,
        modified: sanitizeText(cve.lastModified ?? '', 40) || undefined,
        affected: match.ranges,
        fixedIn: match.fixedIn,
        matchBasis: `Versão ${version} dentro de ${match.ranges.join(' | ')} (${match.criteria.slice(0, 2).join(', ')})`,
        conditions: match.conditions,
        source: 'nvd',
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${id}`,
        references: references(cve),
      });
    }
  }
  return { vulns, discarded };
}

// ───────── Client ─────────

export interface NvdClientOptions {
  fetch: FetchLike;
  apiKey?: string;
  throttle?: Throttle;
  sleep?: Sleep;
}

export function nvdQueryUrl(vendorProduct: string, version: string, startIndex = 0): string {
  const params = new URLSearchParams({
    virtualMatchString: buildMatchString(vendorProduct, version),
    resultsPerPage: String(PAGE_SIZE),
    startIndex: String(startIndex),
  });
  return `${NVD_ENDPOINT}?${params.toString()}&noRejected`;
}

/** Fetches every page of CVEs whose applicability statements match vendor:product at `version`. */
export async function fetchNvd(vendorProduct: string, version: string, opts: NvdClientOptions): Promise<NvdResponse[]> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (opts.apiKey) headers.apiKey = opts.apiKey;
  const pages: NvdResponse[] = [];
  let startIndex = 0;
  for (;;) {
    const page = await requestJson<NvdResponse>(nvdQueryUrl(vendorProduct, version, startIndex), { headers }, {
      fetch: opts.fetch,
      throttle: opts.throttle,
      sleep: opts.sleep,
      label: 'NVD',
      timeoutMs: 45000,
      retries: 2,
      retryDelayMs: 8000,
      rateLimitHint: opts.apiKey
        ? 'Aguarde alguns segundos e tente novamente.'
        : 'Sem chave de API o NVD permite ~5 requisições a cada 30 s; configure uma chave nas opções.',
    });
    if (typeof page?.totalResults !== 'number' || !Array.isArray(page.vulnerabilities)) {
      throw new Error('NVD: formato de resposta inesperado.');
    }
    pages.push(page);
    startIndex += page.resultsPerPage || PAGE_SIZE;
    if (startIndex >= page.totalResults || startIndex >= MAX_RESULTS || page.vulnerabilities.length === 0) break;
  }
  return pages;
}
