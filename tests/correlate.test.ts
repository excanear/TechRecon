import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { correlateDetection, correlationPrecheck, type CachedQuery, type CorrelationContext, type QueryCache } from '../src/cve/correlate';
import { Throttle, type FetchLike } from '../src/cve/http';
import { detectTechnologies } from '../src/fingerprinting/engine';
import type { Detection } from '../src/types';
import { snapshot } from './helpers';

const raw = (name: string) => readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8');

class MemoryCache implements QueryCache {
  readonly store = new Map<string, CachedQuery>();
  async get(key: string) {
    return this.store.get(key);
  }
  async set(key: string, value: CachedQuery) {
    this.store.set(key, value);
  }
}

const noSleep = async () => undefined;

function ctx(fetchImpl: FetchLike, cache = new MemoryCache(), now = () => 1_700_000_000_000): CorrelationContext {
  return {
    fetch: fetchImpl,
    cache,
    cacheTtlMs: 24 * 3600_000,
    nvdThrottle: new Throttle(0, noSleep),
    osvThrottle: new Throttle(0, noSleep),
    sleep: noSleep,
    now,
  };
}

const ok = (body: string) => new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } });

function detect(page: Parameters<typeof snapshot>[0], id: string): Detection {
  const d = detectTechnologies(snapshot(page)).find((x) => x.id === id);
  if (!d) throw new Error(`${id} not detected`);
  return d;
}

describe('CVE correlation', () => {
  it('never queries a source when the version is unknown', async () => {
    const fetchSpy = vi.fn<FetchLike>();
    const det = detect({ scriptSrcs: ['https://example.com/jquery.min.js'] }, 'jquery');
    const report = await correlateDetection(det, ctx(fetchSpy));
    expect(report.status).toBe('no-version');
    expect(report.vulns).toEqual([]);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('never correlates inferred technologies', () => {
    const php = detectTechnologies(snapshot({ meta: { generator: ['WordPress 6.4.2'] } })).find((d) => d.id === 'php')!;
    expect(correlationPrecheck(php)?.status).toBe('no-version');
  });

  it('refuses imprecise or conflicting versions', () => {
    const drupal = detect({ meta: { generator: ['Drupal 10'] } }, 'drupal');
    expect(correlationPrecheck(drupal)?.status).toBe('version-uncertain');
  });

  it('reports unmapped technologies honestly', () => {
    const gtm = detect({ scriptSrcs: ['https://www.googletagmanager.com/gtm.js?id=GTM-X'] }, 'google-tag-manager');
    expect(correlationPrecheck(gtm)?.status).toBe('unmapped');
  });

  it('queries OSV for npm-mapped libraries and returns verified matches', async () => {
    const fetchSpy = vi.fn<FetchLike>(async () => ok(raw('osv-jquery-3.4.1.json')));
    const det = detect({ globals: { 'jQuery.fn.jquery': '3.4.1' } }, 'jquery');
    const report = await correlateDetection(det, ctx(fetchSpy));
    expect(report.status).toBe('ok');
    expect(report.vulns.map((v) => v.id).sort()).toEqual(['CVE-2020-11022', 'CVE-2020-11023']);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe('https://api.osv.dev/v1/query');
    expect(JSON.parse(String(init?.body))).toEqual({ version: '3.4.1', package: { name: 'jquery', ecosystem: 'npm' } });
  });

  it('queries NVD for every CPE alias, merges duplicates and adds backport caveats', async () => {
    const fetchSpy = vi.fn<FetchLike>(async () => ok(raw('nvd-nginx-1.18.0.json')));
    const det = detect({ headers: { server: 'nginx/1.18.0 (Ubuntu)' } }, 'nginx');
    const report = await correlateDetection(det, ctx(fetchSpy));
    expect(fetchSpy).toHaveBeenCalledTimes(2); // f5:nginx and nginx:nginx
    expect(String(fetchSpy.mock.calls[0]![0])).toContain('virtualMatchString=cpe%3A2.3%3Aa%3Af5%3Anginx%3A1.18.0');
    const ids = report.vulns.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(report.vulns.every((v) => v.conditions?.includes('backport'))).toBe(true);
  });

  it('sends the NVD API key only as a header', async () => {
    const fetchSpy = vi.fn<FetchLike>(async () => ok(raw('nvd-jquery-3.4.1.json')));
    const det: Detection = { ...detect({ globals: { 'jQuery.fn.jquery': '3.4.1' } }, 'jquery'), npm: undefined };
    await correlateDetection(det, { ...ctx(fetchSpy), nvdApiKey: 'abc-123' });
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).not.toContain('abc-123');
    expect((init?.headers as Record<string, string>).apiKey).toBe('abc-123');
  });

  it('uses the cache on the second lookup and refreshes after the TTL', async () => {
    const fetchSpy = vi.fn<FetchLike>(async () => ok(raw('osv-jquery-3.4.1.json')));
    const cache = new MemoryCache();
    let now = 1_000_000;
    const det = detect({ globals: { 'jQuery.fn.jquery': '3.4.1' } }, 'jquery');
    await correlateDetection(det, ctx(fetchSpy, cache, () => now));
    const second = await correlateDetection(det, ctx(fetchSpy, cache, () => now));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(second.queries[0]).toMatchObject({ cached: true, ok: true });
    expect(second.vulns).toHaveLength(2);
    now += 25 * 3600_000;
    await correlateDetection(det, ctx(fetchSpy, cache, () => now));
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('reports failures without inventing results and does not cache them', async () => {
    const cache = new MemoryCache();
    const fetchSpy = vi.fn<FetchLike>(async () => new Response('busy', { status: 503 }));
    const det = detect({ globals: { 'jQuery.fn.jquery': '3.4.1' } }, 'jquery');
    const report = await correlateDetection(det, ctx(fetchSpy, cache));
    expect(report.status).toBe('error');
    expect(report.vulns).toEqual([]);
    expect(report.message).toMatch(/OSV: serviço indisponível \(HTTP 503\)/);
    expect(fetchSpy).toHaveBeenCalledTimes(2); // one bounded retry
    expect(cache.store.size).toBe(0);
  });

  it('explains NVD rate limiting', async () => {
    const fetchSpy = vi.fn<FetchLike>(async () => new Response('', { status: 403 }));
    const det = detect({ headers: { server: 'Apache/2.4.41 (Ubuntu)' } }, 'apache-httpd');
    const report = await correlateDetection(det, ctx(fetchSpy));
    expect(report.status).toBe('error');
    expect(report.message).toMatch(/limite de requisições/);
    expect(report.message).toMatch(/chave de API/);
  });

  it('handles network errors and malformed JSON', async () => {
    const det = detect({ globals: { 'jQuery.fn.jquery': '3.4.1' } }, 'jquery');
    const net = await correlateDetection(det, ctx(async () => { throw new TypeError('Failed to fetch'); }));
    expect(net.message).toMatch(/falha de rede/);
    const bad = await correlateDetection(det, ctx(async () => new Response('<html>', { status: 200 })));
    expect(bad.status).toBe('error');
    expect(bad.message).toMatch(/JSON/);
  });
});
