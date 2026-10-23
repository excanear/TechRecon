import type { Detection, SourceQueryResult, TechVulnReport, Vulnerability } from '../types';
import { SEVERITY_RANK } from './cvss';
import { Throttle, type FetchLike, type Sleep } from './http';
import { fetchNvd, normalizeNvdResponse } from './nvd';
import { fetchOsv, normalizeOsvResponse } from './osv';

/** Cached result of one source query (already verified against the version). */
export interface CachedQuery {
  storedAt: number;
  vulns: Vulnerability[];
  discarded: number;
}

export interface QueryCache {
  get(key: string): Promise<CachedQuery | undefined>;
  set(key: string, value: CachedQuery): Promise<void>;
}

export interface CorrelationContext {
  fetch: FetchLike;
  cache: QueryCache;
  nvdApiKey?: string;
  cacheTtlMs: number;
  nvdThrottle: Throttle;
  osvThrottle: Throttle;
  sleep?: Sleep;
  now?: () => number;
}

/** NVD public limits: 5 requests / 30 s without key, 50 / 30 s with key. */
export function nvdIntervalMs(apiKey?: string): number {
  return apiKey ? 700 : 6500;
}

export function createThrottles(apiKey?: string, sleep?: Sleep): { nvd: Throttle; osv: Throttle } {
  return { nvd: new Throttle(nvdIntervalMs(apiKey), sleep), osv: new Throttle(150, sleep) };
}

interface PlannedQuery {
  source: 'nvd' | 'osv';
  query: string;
  cacheKey: string;
  run: () => Promise<{ vulns: Vulnerability[]; discarded: number }>;
}

/**
 * Decides whether a detection can be correlated at all. Correlation by product name alone is
 * never performed: an exact, unambiguous, directly observed version is required.
 */
export function correlationPrecheck(det: Detection): Pick<TechVulnReport, 'status' | 'message'> | null {
  if (!det.cpe?.length && !det.npm) {
    return { status: 'unmapped', message: 'Sem mapeamento CPE/pacote para esta tecnologia; nenhuma fonte consultada.' };
  }
  if (det.inferred) {
    return { status: 'no-version', message: 'Tecnologia inferida (não observada diretamente); correlação não realizada.' };
  }
  if (!det.version) {
    return { status: 'no-version', message: 'Versão não determinada. A correlação por nome isolado não é realizada.' };
  }
  if (det.versionConflicts.length) {
    return {
      status: 'version-uncertain',
      message: `Versões conflitantes observadas (${[det.version, ...det.versionConflicts].join(', ')}); correlação não realizada.`,
    };
  }
  if (!det.versionExact) {
    return { status: 'version-uncertain', message: `Versão "${det.version}" é imprecisa demais para comparar com intervalos afetados.` };
  }
  return null;
}

function planQueries(det: Detection, ctx: CorrelationContext): PlannedQuery[] {
  const version = det.version!;
  if (det.npm) {
    const pkg = det.npm;
    return [
      {
        source: 'osv',
        query: `npm/${pkg}@${version}`,
        cacheKey: `osv:npm:${pkg}@${version}`,
        run: async () =>
          normalizeOsvResponse(await fetchOsv('npm', pkg, version, { fetch: ctx.fetch, throttle: ctx.osvThrottle, sleep: ctx.sleep }), 'npm', pkg, version),
      },
    ];
  }
  const cpes = det.cpe ?? [];
  return cpes.map((vp) => ({
    source: 'nvd' as const,
    query: `cpe:2.3:a:${vp}:${version}`,
    cacheKey: `nvd:${vp}:${version}`,
    // Every CPE alias of the product is used for local verification (e.g. f5:nginx and nginx:nginx).
    run: async () =>
      normalizeNvdResponse(
        await fetchNvd(vp, version, { fetch: ctx.fetch, apiKey: ctx.nvdApiKey, throttle: ctx.nvdThrottle, sleep: ctx.sleep }),
        cpes,
        version,
      ),
  }));
}

function mergeVulns(lists: Vulnerability[][]): Vulnerability[] {
  const byId = new Map<string, Vulnerability>();
  const aliasToId = new Map<string, string>();
  for (const v of lists.flat()) {
    const existingId = [v.id, ...v.aliases].map((k) => aliasToId.get(k) ?? (byId.has(k) ? k : undefined)).find(Boolean);
    if (existingId) {
      const cur = byId.get(existingId)!;
      cur.aliases = [...new Set([...cur.aliases, ...v.aliases, v.id].filter((a) => a !== cur.id))];
      cur.affected = [...new Set([...cur.affected, ...v.affected])];
      cur.fixedIn ??= v.fixedIn;
      continue;
    }
    byId.set(v.id, { ...v });
    for (const a of v.aliases) aliasToId.set(a, v.id);
  }
  return [...byId.values()].sort(
    (a, b) =>
      (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      b.id.localeCompare(a.id),
  );
}

export async function correlateDetection(det: Detection, ctx: CorrelationContext): Promise<TechVulnReport> {
  const base = { techId: det.id, techName: det.name, version: det.version };
  const blocked = correlationPrecheck(det);
  if (blocked) return { ...base, ...blocked, queries: [], vulns: [] };

  const now = ctx.now ?? Date.now;
  const queries: SourceQueryResult[] = [];
  const lists: Vulnerability[][] = [];

  for (const planned of planQueries(det, ctx)) {
    const cached = await ctx.cache.get(planned.cacheKey).catch(() => undefined);
    if (cached && now() - cached.storedAt < ctx.cacheTtlMs) {
      queries.push({
        source: planned.source,
        query: planned.query,
        ok: true,
        cached: true,
        fetchedAt: new Date(cached.storedAt).toISOString(),
        discarded: cached.discarded,
      });
      lists.push(cached.vulns);
      continue;
    }
    try {
      const result = await planned.run();
      const storedAt = now();
      // Only successful responses are cached; failures are retried on the next analysis.
      await ctx.cache.set(planned.cacheKey, { storedAt, vulns: result.vulns, discarded: result.discarded }).catch(() => undefined);
      queries.push({
        source: planned.source,
        query: planned.query,
        ok: true,
        cached: false,
        fetchedAt: new Date(storedAt).toISOString(),
        discarded: result.discarded,
      });
      lists.push(result.vulns);
    } catch (err) {
      queries.push({
        source: planned.source,
        query: planned.query,
        ok: false,
        cached: false,
        error: err instanceof Error ? err.message : String(err),
        discarded: 0,
      });
    }
  }

  const failed = queries.filter((q) => !q.ok);
  let vulns = mergeVulns(lists);
  if (det.distroPackage) {
    const note = `Banner de pacote ${det.distroPackage}: verifique se a correção foi aplicada por backport.`;
    vulns = vulns.map((v) => ({ ...v, conditions: v.conditions ? `${v.conditions} · ${note}` : note }));
  }

  if (failed.length === queries.length) {
    return { ...base, status: 'error', message: failed.map((q) => q.error).join(' '), queries, vulns: [] };
  }
  return {
    ...base,
    status: 'ok',
    message: failed.length ? `Consulta parcial: ${failed.map((q) => q.error).join(' ')}` : undefined,
    queries,
    vulns,
  };
}
