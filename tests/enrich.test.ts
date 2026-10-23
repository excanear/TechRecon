import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AggregatedTech } from '../src/crawler/aggregate';
import { comparePriority, cveIdsOf, dedupeFindings, enrichVulns, formatEpss, priorityTier, type EnrichmentContext } from '../src/cve/enrich';
import { fetchEpss, parseEpssResponse, type EpssResponse } from '../src/cve/epss';
import { loadKevCatalog, parseKevCatalog, type KevCatalog, type KevStore } from '../src/cve/kev';
import { normalizeNvdResponse, type NvdResponse } from '../src/cve/nvd';
import { normalizeOsvResponse, type OsvResponse } from '../src/cve/osv';
import { closeDb, getAllByIndex } from '../src/db';
import { runCvePhase } from '../src/scan/cvePhase';
import type { ScanSession, TechCveRecord, VulnFindingRecord } from '../src/scan/types';
import { emptyCounters } from '../src/scan/types';
import type { TechVulnReport, Vulnerability } from '../src/types';

// Real responses: FIRST EPSS for the fixture CVEs, a verbatim subset of the CISA KEV catalog,
// and the recorded NVD/OSV responses (see tests/fixtures/README.md).
const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8')) as T;
const EPSS = fixture<EpssResponse>('epss-fixture-cves.json');
const KEV_RAW = fixture<Parameters<typeof parseKevCatalog>[0]>('kev-subset.json');

const jqueryNvd = () => normalizeNvdResponse([fixture<NvdResponse>('nvd-jquery-3.4.1.json')], ['jquery:jquery'], '3.4.1').vulns;
const jqueryOsv = () => normalizeOsvResponse([fixture<OsvResponse>('osv-jquery-3.4.1.json')], 'npm', 'jquery', '3.4.1').vulns;
const nginxNvd = () => normalizeNvdResponse([fixture<NvdResponse>('nvd-nginx-1.18.0.json')], ['f5:nginx', 'nginx:nginx'], '1.18.0').vulns;

/** Serves the recorded EPSS response, filtered to the CVEs asked for (as the real API does). */
function epssFetch() {
  return vi.fn(async (url: string) => {
    const asked = new Set(new URL(url).searchParams.get('cve')!.split(','));
    const data = EPSS.data!.filter((r) => asked.has(r.cve as string));
    return new Response(JSON.stringify({ ...EPSS, total: data.length, data }), { status: 200 });
  });
}

const kevCatalog = (): KevCatalog => parseKevCatalog(KEV_RAW, '2026-10-23T00:00:00.000Z');

function ctx(over: Partial<EnrichmentContext> = {}): EnrichmentContext {
  return { fetch: epssFetch(), kev: async () => ({ catalog: kevCatalog(), stale: false }), ...over };
}

describe('EPSS', () => {
  it('parses scores as numbers and drops malformed rows', () => {
    const scores = parseEpssResponse(EPSS);
    expect(scores.get('CVE-2020-11023')).toEqual({ cve: 'CVE-2020-11023', score: 0.84887, percentile: 0.99714, date: '2026-10-23' });
    const bad = parseEpssResponse({ status: 'OK', data: [{ cve: 'CVE-2020-1', epss: '0.5', percentile: '0.5' }, { cve: 'CVE-2020-11023', epss: 'x', percentile: '0.1' }] });
    expect(bad.size).toBe(0);
    expect(() => parseEpssResponse({ status: 'error' })).toThrow(/formato/);
  });

  it('reports CVEs without a published score as null, not 0', async () => {
    const result = await fetchEpss(['CVE-2020-23064', 'CVE-2020-11022'], { fetch: epssFetch() });
    expect(result.get('CVE-2020-23064')).toBeNull();
    expect(result.get('CVE-2020-11022')!.score).toBeCloseTo(0.99215);
  });

  it('batches at 100 CVEs per request', async () => {
    const fetchFn = epssFetch();
    const ids = Array.from({ length: 150 }, (_, i) => `CVE-2024-${String(10000 + i)}`);
    const result = await fetchEpss(ids, { fetch: fetchFn });
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(result.size).toBe(150);
  });
});

describe('CISA KEV', () => {
  it('parses the catalog and the ransomware flag', () => {
    const catalog = kevCatalog();
    expect(catalog.catalogVersion).toBe('2026.10.21');
    expect(Object.keys(catalog.entries)).toHaveLength(4);
    expect(catalog.entries['CVE-2020-11023']).toMatchObject({ dateAdded: '2025-01-23', dueDate: '2025-02-13', ransomware: false });
    expect(Object.values(catalog.entries).filter((e) => e.ransomware)).toHaveLength(1);
    expect(() => parseKevCatalog({ vulnerabilities: [] }, '')).toThrow(/formato/);
  });

  const memoryStore = (initial?: KevCatalog): KevStore & { saved?: KevCatalog } => {
    const store: KevStore & { saved?: KevCatalog } = {
      saved: initial,
      get: async () => store.saved,
      set: async (c) => {
        store.saved = c;
      },
    };
    return store;
  };
  const NOW = Date.parse('2026-10-23T12:00:00Z');

  it('uses a fresh stored catalog without downloading', async () => {
    const fetchFn = vi.fn();
    const load = await loadKevCatalog({ fetch: fetchFn, store: memoryStore(kevCatalog()), maxAgeMs: 24 * 3600_000, now: () => NOW });
    expect(fetchFn).not.toHaveBeenCalled();
    expect(load.stale).toBe(false);
  });

  it('downloads and stores when there is no catalog', async () => {
    const store = memoryStore();
    const fetchFn = vi.fn(async () => new Response(JSON.stringify(KEV_RAW), { status: 200 }));
    const load = await loadKevCatalog({ fetch: fetchFn, store, maxAgeMs: 1, now: () => NOW });
    expect(fetchFn).toHaveBeenCalledWith(expect.stringContaining('known_exploited_vulnerabilities.json'), expect.anything());
    expect(store.saved?.catalogVersion).toBe('2026.10.21');
    expect(load.catalog.fetchedAt).toBe(new Date(NOW).toISOString());
  });

  it('falls back to a stale copy only when the refresh fails, and says so', async () => {
    const down = vi.fn(async () => new Response('', { status: 503 }));
    const stale = await loadKevCatalog({ fetch: down, store: memoryStore(kevCatalog()), maxAgeMs: 1, now: () => NOW, sleep: async () => undefined });
    expect(stale.stale).toBe(true);
    expect(stale.refreshError).toMatch(/503/);
    await expect(loadKevCatalog({ fetch: down, store: memoryStore(), maxAgeMs: 1, now: () => NOW, sleep: async () => undefined })).rejects.toThrow(/503/);
  });
});

describe('enrichVulns', () => {
  it('marks jQuery 3.4.1 CVE-2020-11023 as KEV and scores both CVEs', async () => {
    const vulns = jqueryNvd();
    const status = await enrichVulns(vulns, ctx());
    const byId = Object.fromEntries(vulns.map((v) => [v.id, v]));
    expect(byId['CVE-2020-11023']!.kev).toMatchObject({ dateAdded: '2025-01-23' });
    expect(byId['CVE-2020-11022']!.kev).toBeNull();
    expect(byId['CVE-2020-11022']!.epss!.score).toBeCloseTo(0.99215);
    expect(status).toMatchObject({ cves: 2, kev: { ok: true, listed: 1, catalogVersion: '2026.10.21' }, epss: { ok: true, scored: 2, date: '2026-10-23' } });
  });

  it('distinguishes "no EPSS score" (null) from "EPSS unavailable" (undefined)', async () => {
    // An advisory with no CVE alias (common for GHSA-only advisories): EPSS and KEV only cover
    // CVEs, so it is "checked, nothing published" — not "unknown".
    const osv = jqueryOsv();
    const advisoryOnly = { ...osv[0]!, id: osv[0]!.aliases.find((a) => a.startsWith('GHSA-')) ?? 'GHSA-gxr4-xjj5-5px2', aliases: [] };
    await enrichVulns([advisoryOnly], ctx());
    expect(advisoryOnly.epss).toBeNull();
    expect(advisoryOnly.kev).toBeNull();

    const fresh = jqueryOsv();
    const status = await enrichVulns(fresh, ctx({ fetch: vi.fn(async () => new Response('', { status: 500 })), sleep: async () => undefined }));
    expect(fresh.every((v) => v.epss === undefined)).toBe(true);
    expect(status.epss).toMatchObject({ ok: false, error: expect.stringMatching(/EPSS.*500/) });
    expect(status.kev.ok).toBe(true);
  });

  it('leaves KEV unknown when the catalog cannot be loaded', async () => {
    const vulns = jqueryNvd();
    const status = await enrichVulns(vulns, ctx({ kev: async () => Promise.reject(new Error('CISA KEV: falha de rede')) }));
    expect(vulns.every((v) => v.kev === undefined)).toBe(true);
    expect(status.kev).toMatchObject({ ok: false, error: 'CISA KEV: falha de rede' });
  });
});

describe('priority', () => {
  const v = (id: string, score: number | null, over: Partial<Vulnerability> = {}): Vulnerability => ({
    id,
    aliases: [],
    title: id,
    description: '',
    cvss: score === null ? null : { version: '3.1', score, vector: '', severity: score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : 'MEDIUM' },
    severity: score === null ? 'UNKNOWN' : score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : 'MEDIUM',
    affected: [],
    matchBasis: '',
    source: 'nvd',
    sourceUrl: '',
    references: [],
    ...over,
  });
  const epss = (score: number) => ({ cve: 'x', score, percentile: 0.5, date: '' });
  const kev = { cve: 'x', name: '', dateAdded: '', dueDate: '', ransomware: false, requiredAction: '' };

  it('orders KEV, then EPSS band, then CVSS', () => {
    const list = [
      v('critical-unlikely', 9.8, { epss: epss(0.001) }),
      v('medium-likely', 5.3, { epss: epss(0.4) }),
      v('medium-kev', 6.1, { kev, epss: epss(0.05) }),
      v('high-medium-band', 7.5, { epss: epss(0.02) }),
      v('unknown', null),
    ];
    expect(list.sort(comparePriority).map((x) => x.id)).toEqual(['medium-kev', 'medium-likely', 'high-medium-band', 'critical-unlikely', 'unknown']);
    expect(priorityTier(list[0]!)).toBe('kev');
  });

  it('formats EPSS by truncation, never rounding up to a certainty', () => {
    expect(formatEpss(0.99999)).toBe('99.9%');
    expect(formatEpss(0.84887)).toBe('84.8%');
    expect(formatEpss(0.00402)).toBe('0.40%');
  });

  it('ranks real data: nginx HTTP/2 Rapid Reset (KEV) above higher-CVSS nginx CVEs', async () => {
    const vulns = nginxNvd();
    await enrichVulns(vulns, ctx());
    vulns.sort(comparePriority);
    expect(vulns[0]!.id).toBe('CVE-2023-44487');
    expect(vulns[0]!.kev).toBeTruthy();
  });
});

describe('dedupeFindings', () => {
  const report = (techId: string, vulns: Vulnerability[]): TechVulnReport => ({ techId, techName: techId, version: '1', status: 'ok', queries: [], vulns });

  it('lists a CVE matched through two technologies once, with both', () => {
    const findings = dedupeFindings([report('jquery', jqueryNvd()), report('jquery-cdn', jqueryNvd())]);
    expect(findings).toHaveLength(2);
    expect(findings[0]!.techs.map((t) => t.id)).toEqual(['jquery', 'jquery-cdn']);
  });

  it('merges an advisory with the CVE it aliases', () => {
    const nvd = jqueryNvd();
    const osv = jqueryOsv();
    const findings = dedupeFindings([report('a', nvd), report('b', osv)]);
    const ids = new Set(findings.flatMap((f) => cveIdsOf(f.vuln)));
    // Every CVE appears in exactly one finding.
    expect(findings.flatMap((f) => cveIdsOf(f.vuln)).length).toBe(ids.size);
    expect(findings.find((f) => cveIdsOf(f.vuln).includes('CVE-2020-11023'))!.techs.map((t) => t.id).sort()).toEqual(['a', 'b']);
  });
});

describe('runCvePhase', () => {
  beforeEach(async () => {
    await closeDb();
    await new Promise<void>((resolve) => {
      const req = indexedDB.deleteDatabase('techrecon');
      req.onsuccess = req.onerror = req.onblocked = () => resolve();
    });
  });

  const tech = (id: string, over: Partial<AggregatedTech> = {}): AggregatedTech => ({
    id,
    name: id,
    categories: ['js-library'],
    confidence: 100,
    confidenceLevel: 'high',
    version: '3.4.1',
    versionExact: true,
    versionConflicts: [],
    inferred: false,
    evidence: [],
    notes: [],
    cpe: ['jquery:jquery'],
    pageCount: 3,
    samplePages: [],
    ...over,
  });
  const session = (): ScanSession => ({
    id: 's1',
    label: 'x',
    scope: { seeds: [], includeHosts: [], excludePatterns: [], maxDepth: 1, maxPages: 1, requestsPerSecond: 1, concurrency: 1, followSubdomains: false },
    authorization: { acknowledged: true, statement: 'x', at: '' },
    status: 'running',
    counters: emptyCounters(),
    createdAt: '',
  });

  it('queries only eligible technologies, dedupes, enriches, ranks and persists', async () => {
    const s = session();
    const correlate = vi.fn(async (t: { id: string; name: string; version?: string }): Promise<TechVulnReport> =>
      t.id === 'nginx'
        ? { techId: t.id, techName: t.name, version: t.version, status: 'error', message: 'NVD: tempo esgotado.', queries: [], vulns: [] }
        : { techId: t.id, techName: t.name, version: t.version, status: 'ok', queries: [], vulns: jqueryNvd() },
    );
    const inventory = [
      tech('jquery'),
      tech('jquery-migrate-bundle'),
      tech('nginx', { cpe: ['f5:nginx'], version: '1.18.0' }),
      tech('php', { inferred: true, version: undefined, cpe: ['php:php'] }),
      tech('font', { cpe: undefined }),
    ];
    const records = await runCvePhase(s, inventory, { correlate, enrich: (v) => enrichVulns(v, ctx()) }, { shouldContinue: () => true, onUpdate: () => undefined });

    expect(correlate).toHaveBeenCalledTimes(3);
    expect(s.cve).toMatchObject({ status: 'done', total: 5, eligible: 3, done: 3, errors: 1 });
    expect(records.map((r) => r.vuln.id)).toEqual(['CVE-2020-11023', 'CVE-2020-11022']);
    expect(records[0]!.techs.map((t) => t.id)).toEqual(['jquery', 'jquery-migrate-bundle']);
    expect(s.counters).toMatchObject({ vulnerabilities: 2, exploited: 1 });

    const stored = await getAllByIndex<VulnFindingRecord>('vulnFindings', 'sessionId', 's1');
    expect(stored.find((r) => r.rank === 0)!.vuln.kev).toBeTruthy();
    const perTech = await getAllByIndex<TechCveRecord>('techCve', 'sessionId', 's1');
    expect(Object.fromEntries(perTech.map((r) => [r.techId, r.status]))).toEqual({
      jquery: 'ok',
      'jquery-migrate-bundle': 'ok',
      nginx: 'error',
      php: 'no-version',
      font: 'unmapped',
    });
  });

  it('stops querying on abort and keeps what was already found', async () => {
    const s = session();
    let calls = 0;
    const correlate = vi.fn(async (t: { id: string; name: string; version?: string }): Promise<TechVulnReport> => {
      calls++;
      return { techId: t.id, techName: t.name, version: t.version, status: 'ok', queries: [], vulns: jqueryNvd() };
    });
    await runCvePhase(s, [tech('a'), tech('b'), tech('c')], { correlate, enrich: (v) => enrichVulns(v, ctx()) }, { shouldContinue: () => calls < 1, onUpdate: () => undefined });
    expect(correlate).toHaveBeenCalledTimes(1);
    expect(s.cve).toMatchObject({ status: 'aborted', done: 1 });
    expect(s.counters.vulnerabilities).toBe(2);
  });
});
