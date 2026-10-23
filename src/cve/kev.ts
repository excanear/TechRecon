// CISA Known Exploited Vulnerabilities catalog: CVEs with evidence of exploitation in the wild.
// The whole catalog (~1.8 MB) is downloaded, reduced to the fields shown, and cached locally;
// lookups are then offline. A stale copy is only used when a refresh fails, and is labelled so.

import type { KevInfo } from '../types';
import { requestJson, type FetchLike, type Sleep } from './http';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

export interface KevCatalog {
  /** IndexedDB key. */
  id: 'kev';
  catalogVersion: string;
  dateReleased: string;
  fetchedAt: string;
  entries: Record<string, KevInfo>;
}

interface RawKev {
  catalogVersion?: unknown;
  dateReleased?: unknown;
  vulnerabilities?: Array<Record<string, unknown>>;
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function parseKevCatalog(body: RawKev, fetchedAt: string): KevCatalog {
  if (!body || !Array.isArray(body.vulnerabilities) || typeof body.catalogVersion !== 'string') {
    throw new Error('CISA KEV: formato de catálogo inesperado.');
  }
  const entries: Record<string, KevInfo> = {};
  for (const v of body.vulnerabilities) {
    const cve = str(v.cveID);
    if (!CVE_ID.test(cve)) continue;
    entries[cve] = {
      cve,
      name: str(v.vulnerabilityName),
      dateAdded: str(v.dateAdded),
      dueDate: str(v.dueDate),
      ransomware: str(v.knownRansomwareCampaignUse).toLowerCase() === 'known',
      requiredAction: str(v.requiredAction),
    };
  }
  if (!Object.keys(entries).length) throw new Error('CISA KEV: catálogo sem entradas válidas.');
  return { id: 'kev', catalogVersion: body.catalogVersion, dateReleased: str(body.dateReleased), fetchedAt, entries };
}

export interface KevStore {
  get(): Promise<KevCatalog | undefined>;
  set(catalog: KevCatalog): Promise<void>;
}

export interface KevLoadOptions {
  fetch: FetchLike;
  store: KevStore;
  /** Refresh after this age. */
  maxAgeMs: number;
  now?: () => number;
  sleep?: Sleep;
}

export interface KevLoad {
  catalog: KevCatalog;
  /** True when a refresh failed and an older stored catalog is being used. */
  stale: boolean;
  refreshError?: string;
}

/** Stored catalog if fresh; otherwise downloads. Falls back to a stale copy only on failure. */
export async function loadKevCatalog(opts: KevLoadOptions): Promise<KevLoad> {
  const now = opts.now ?? Date.now;
  const stored = await opts.store.get().catch(() => undefined);
  if (stored && now() - Date.parse(stored.fetchedAt) < opts.maxAgeMs) return { catalog: stored, stale: false };
  try {
    const body = await requestJson<RawKev>(KEV_URL, { headers: { Accept: 'application/json' } }, {
      fetch: opts.fetch,
      sleep: opts.sleep,
      label: 'CISA KEV',
      timeoutMs: 60000,
      retries: 1,
      retryDelayMs: 3000,
    });
    const catalog = parseKevCatalog(body, new Date(now()).toISOString());
    await opts.store.set(catalog).catch(() => undefined);
    return { catalog, stale: false };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (stored) return { catalog: stored, stale: true, refreshError: message };
    throw new Error(message);
  }
}
