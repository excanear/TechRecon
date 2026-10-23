// FIRST EPSS (Exploit Prediction Scoring System): probability that a CVE is exploited in the
// next 30 days. Batched lookups; a CVE missing from the response has no published score, which
// is reported as such (null), never as 0.

import type { EpssInfo } from '../types';
import { requestJson, type FetchLike, type Sleep, type Throttle } from './http';

export const EPSS_API = 'https://api.first.org/data/v1/epss';
/** The API pages at 100 rows; one batch never asks for more CVEs than one page holds. */
const BATCH = 100;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

export interface EpssResponse {
  status?: string;
  total?: number;
  data?: Array<{ cve?: unknown; epss?: unknown; percentile?: unknown; date?: unknown }>;
}

export interface EpssClientOptions {
  fetch: FetchLike;
  throttle?: Throttle;
  sleep?: Sleep;
}

/** Valid rows of one response, keyed by CVE. Malformed rows are dropped. */
export function parseEpssResponse(body: EpssResponse): Map<string, EpssInfo> {
  if (body?.status !== 'OK' || !Array.isArray(body.data)) throw new Error('EPSS: formato de resposta inesperado.');
  const out = new Map<string, EpssInfo>();
  for (const row of body.data) {
    const score = Number(row.epss);
    const percentile = Number(row.percentile);
    if (typeof row.cve !== 'string' || !CVE_ID.test(row.cve)) continue;
    if (!Number.isFinite(score) || score < 0 || score > 1 || !Number.isFinite(percentile) || percentile < 0 || percentile > 1) continue;
    out.set(row.cve, { cve: row.cve, score, percentile, date: typeof row.date === 'string' ? row.date : '' });
  }
  return out;
}

/**
 * Scores for the given CVEs. Every requested id ends up in the result: an EpssInfo when scored,
 * null when EPSS has no score for it. Any failed batch rejects the whole lookup.
 */
export async function fetchEpss(cves: string[], opts: EpssClientOptions): Promise<Map<string, EpssInfo | null>> {
  const ids = [...new Set(cves.filter((c) => CVE_ID.test(c)))].sort();
  const out = new Map<string, EpssInfo | null>();
  for (let i = 0; i < ids.length; i += BATCH) {
    const batch = ids.slice(i, i + BATCH);
    const body = await requestJson<EpssResponse>(`${EPSS_API}?cve=${batch.join(',')}`, { headers: { Accept: 'application/json' } }, {
      fetch: opts.fetch,
      throttle: opts.throttle,
      sleep: opts.sleep,
      label: 'EPSS',
      timeoutMs: 30000,
      retries: 1,
      retryDelayMs: 3000,
    });
    const scored = parseEpssResponse(body);
    for (const id of batch) out.set(id, scored.get(id) ?? null);
  }
  return out;
}
