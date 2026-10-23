// Vulnerability-intelligence plumbing shared by the single-page analysis and site scans. One
// cache and one set of throttles for the whole service worker, so a scan and a popup analysis
// running together still respect the NVD/OSV/EPSS rate limits.

import { createThrottles, nvdIntervalMs, type CorrelationContext } from '../cve/correlate';
import type { EnrichmentContext } from '../cve/enrich';
import { Throttle } from '../cve/http';
import { loadKevCatalog, type KevCatalog, type KevLoad, type KevStore } from '../cve/kev';
import { get, put } from '../db';
import { ChromeQueryCache } from '../storage';
import type { Settings } from '../types';

export const cache = new ChromeQueryCache();
const throttles = createThrottles();
const epssThrottle = new Throttle(1000);

/** KEV is published about once a day. */
const KEV_MAX_AGE_MS = 24 * 3600_000;

const kevStore: KevStore = {
  get: () => get<KevCatalog>('datasets', 'kev'),
  set: (catalog) => put('datasets', catalog).then(() => undefined),
};

let kevMemo: { at: number; load: Promise<KevLoad> } | null = null;

/** Loads the KEV catalog at most once per few minutes per worker (the store has its own TTL). */
function loadKev(): Promise<KevLoad> {
  const fresh = kevMemo && Date.now() - kevMemo.at < 5 * 60_000;
  if (!fresh) {
    const load = loadKevCatalog({ fetch: (input, init) => fetch(input, init), store: kevStore, maxAgeMs: KEV_MAX_AGE_MS });
    kevMemo = { at: Date.now(), load };
    // A failed load is not memoized: the next enrichment retries.
    load.catch(() => {
      if (kevMemo?.load === load) kevMemo = null;
    });
  }
  return kevMemo!.load;
}

export function correlationContext(settings: Settings): CorrelationContext {
  throttles.nvd.intervalMs = nvdIntervalMs(settings.nvdApiKey);
  return {
    fetch: (input, init) => fetch(input, init),
    cache,
    nvdApiKey: settings.nvdApiKey || undefined,
    cacheTtlMs: settings.cacheTtlHours * 3600_000,
    nvdThrottle: throttles.nvd,
    osvThrottle: throttles.osv,
  };
}

export function enrichmentContext(): EnrichmentContext {
  return { fetch: (input, init) => fetch(input, init), kev: loadKev, epssThrottle };
}
