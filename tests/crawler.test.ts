import { describe, expect, it, vi } from 'vitest';
import { TechAggregator } from '../src/crawler/aggregate';
import { crawl } from '../src/crawler/crawler';
import type { FetchedPage } from '../src/crawler/types';
import { HostRateLimiter } from '../src/scope/limits';
import { scopeFromSeeds } from '../src/scope/scope';
import type { Detection, PageSnapshot } from '../src/types';

function emptySnapshot(url: string, over: Partial<PageSnapshot> = {}): PageSnapshot {
  return { url, html: '', scriptSrcs: [], inlineScripts: '', stylesheets: [], meta: {}, cookieNames: [], headers: null, globals: {}, dom: {}, resources: [], ...over };
}

/** A fake site: a map of url → { links, snapshot }. */
function fakeSite(pages: Record<string, { links?: string[]; snapshot?: Partial<PageSnapshot>; status?: number }>) {
  const fetched: string[] = [];
  const fetcher = vi.fn(async (url: string): Promise<FetchedPage> => {
    fetched.push(url);
    const page = pages[url];
    if (!page) {
      return { requestedUrl: url, finalUrl: url, ok: false, status: 404, contentType: 'text/html', headers: {}, links: [], snapshot: emptySnapshot(url), bytes: 0, error: 'HTTP 404', skippedReason: 'error' };
    }
    return {
      requestedUrl: url,
      finalUrl: url,
      ok: true,
      status: page.status ?? 200,
      contentType: 'text/html',
      headers: {},
      links: page.links ?? [],
      snapshot: emptySnapshot(url, page.snapshot),
      bytes: 100,
    };
  });
  return { fetcher, fetched };
}

const noRate = new HostRateLimiter(1000, async () => undefined, () => 0);

describe('crawler BFS', () => {
  it('crawls in-scope links breadth-first and dedupes', async () => {
    const { fetcher, fetched } = fakeSite({
      'https://example.com/': { links: ['/a', '/b', '/a'] },
      'https://example.com/a': { links: ['/c', '/'] },
      'https://example.com/b': { links: ['/c'] },
      'https://example.com/c': { links: [] },
    });
    const pages: string[] = [];
    const summary = await crawl(scopeFromSeeds(['https://example.com/']), { fetcher, rateLimiter: noRate }, { onPage: (p) => { pages.push(p.finalUrl); } });
    expect(summary.fetched).toBe(4);
    expect(new Set(fetched).size).toBe(4); // each page fetched once
    expect(pages.sort()).toEqual(['https://example.com/', 'https://example.com/a', 'https://example.com/b', 'https://example.com/c']);
  });

  it('stays within the host and ignores out-of-scope links', async () => {
    const { fetcher, fetched } = fakeSite({
      'https://example.com/': { links: ['https://evil.com/x', 'https://sub.example.com/y', '/ok'] },
      'https://example.com/ok': { links: [] },
    });
    await crawl(scopeFromSeeds(['https://example.com/']), { fetcher, rateLimiter: noRate }, { onPage: () => {} });
    expect(fetched).toEqual(['https://example.com/', 'https://example.com/ok']);
  });

  it('follows subdomains only when enabled', async () => {
    const site = fakeSite({
      'https://example.com/': { links: ['https://api.example.com/y'] },
      'https://api.example.com/y': { links: [] },
    });
    const scope = scopeFromSeeds(['https://example.com/'], { includeHosts: [{ pattern: '*.example.com' }], followSubdomains: true });
    await crawl(scope, { fetcher: site.fetcher, rateLimiter: noRate }, { onPage: () => {} });
    expect(site.fetched).toContain('https://api.example.com/y');
  });

  it('never follows destructive or non-document links', async () => {
    const { fetcher, fetched } = fakeSite({
      'https://example.com/': { links: ['/logout', '/posts/1/delete', '/file.pdf', '/x?action=delete', '/safe'] },
      'https://example.com/safe': { links: [] },
    });
    await crawl(scopeFromSeeds(['https://example.com/']), { fetcher, rateLimiter: noRate }, { onPage: () => {} });
    expect(fetched).toEqual(['https://example.com/', 'https://example.com/safe']);
  });

  it('respects maxDepth', async () => {
    const { fetcher } = fakeSite({
      'https://example.com/': { links: ['/d1'] },
      'https://example.com/d1': { links: ['/d2'] },
      'https://example.com/d2': { links: ['/d3'] },
      'https://example.com/d3': { links: [] },
    });
    const byDepth: Record<number, string[]> = {};
    await crawl(scopeFromSeeds(['https://example.com/'], { maxDepth: 1 }), { fetcher, rateLimiter: noRate }, {
      onPage: (p, depth) => { (byDepth[depth] ??= []).push(p.finalUrl); },
    });
    expect(Object.keys(byDepth)).toEqual(['0', '1']);
    expect(byDepth[1]).toEqual(['https://example.com/d1']);
  });

  it('enforces an exact maxPages ceiling even with concurrency', async () => {
    const pages: Record<string, { links: string[] }> = {};
    for (let i = 0; i < 50; i++) pages[`https://example.com/p${i}`] = { links: Array.from({ length: 50 }, (_, j) => `/p${j}`) };
    pages['https://example.com/'] = { links: Array.from({ length: 50 }, (_, j) => `/p${j}`) };
    const { fetcher } = fakeSite(pages);
    const summary = await crawl(scopeFromSeeds(['https://example.com/'], { maxPages: 10, concurrency: 5, maxDepth: 5 }), { fetcher, rateLimiter: noRate }, { onPage: () => {} });
    expect(summary.fetched).toBe(10);
    expect(summary.reachedLimit).toBe(true);
  });

  it('can be aborted mid-crawl', async () => {
    const pages: Record<string, { links: string[] }> = { 'https://example.com/': { links: Array.from({ length: 20 }, (_, j) => `/p${j}`) } };
    for (let i = 0; i < 20; i++) pages[`https://example.com/p${i}`] = { links: [] };
    const { fetcher } = fakeSite(pages);
    let count = 0;
    const summary = await crawl(scopeFromSeeds(['https://example.com/'], { concurrency: 1 }), { fetcher, rateLimiter: noRate }, {
      onPage: () => { count++; },
      shouldContinue: () => count < 3,
    });
    expect(summary.aborted).toBe(true);
    expect(summary.fetched).toBeLessThanOrEqual(4);
  });

  it('counts errors and skips without throwing', async () => {
    const { fetcher } = fakeSite({ 'https://example.com/': { links: ['/missing'] } });
    const summary = await crawl(scopeFromSeeds(['https://example.com/']), { fetcher, rateLimiter: noRate }, { onPage: () => {} });
    expect(summary.fetched).toBe(2);
    expect(summary.errors).toBe(1);
  });

  it('runs detection on each page and reports technologies', async () => {
    const { fetcher } = fakeSite({
      'https://example.com/': { links: ['/a'], snapshot: { globals: { 'jQuery.fn.jquery': '3.4.1' } } },
      'https://example.com/a': { snapshot: { headers: { server: 'nginx/1.18.0' } } },
    });
    const detById: Record<string, Detection[]> = {};
    await crawl(scopeFromSeeds(['https://example.com/']), { fetcher, rateLimiter: noRate }, {
      onPage: (p, _d, dets) => { detById[p.finalUrl] = dets; },
    });
    expect(detById['https://example.com/']!.some((d) => d.id === 'jquery')).toBe(true);
    expect(detById['https://example.com/a']!.some((d) => d.id === 'nginx')).toBe(true);
  });
});

describe('site-wide aggregation', () => {
  const det = (over: Partial<Detection>): Detection => ({
    id: 'jquery', name: 'jQuery', categories: ['js-library'], confidence: 100, confidenceLevel: 'high',
    versionExact: false, versionConflicts: [], inferred: false, evidence: [], notes: [], ...over,
  });

  it('merges a technology across pages, counting pages and keeping evidence', () => {
    const agg = new TechAggregator();
    agg.add([det({ version: '3.4.1', evidence: [{ type: 'scriptSrc', value: 'jquery-3.4.1.js', version: '3.4.1', confidence: 100, observed: true }] })], 'https://x/a');
    agg.add([det({ version: '3.4.1', evidence: [{ type: 'global', key: 'jQuery.fn.jquery', value: '3.4.1', version: '3.4.1', confidence: 100, observed: true }] })], 'https://x/b');
    const [tech] = agg.finish();
    expect(tech!.pageCount).toBe(2);
    expect(tech!.version).toBe('3.4.1');
    expect(tech!.versionExact).toBe(true);
    expect(tech!.evidence.length).toBe(2);
    expect(tech!.samplePages).toEqual(['https://x/a', 'https://x/b']);
  });

  it('a later observed detection overrides an earlier inference', () => {
    const agg = new TechAggregator();
    agg.add([det({ id: 'php', name: 'PHP', inferred: true, evidence: [{ type: 'implied', value: 'de WordPress', confidence: 50, observed: false }] })], 'https://x/a');
    agg.add([det({ id: 'php', name: 'PHP', inferred: false, evidence: [{ type: 'header', key: 'x-powered-by', value: 'PHP/8.1', version: '8.1', confidence: 100, observed: true }] })], 'https://x/b');
    const [tech] = agg.finish();
    expect(tech!.inferred).toBe(false);
    expect(tech!.version).toBe('8.1');
  });

  it('flags conflicting versions seen across the site', () => {
    const agg = new TechAggregator();
    agg.add([det({ version: '3.6.0', evidence: [{ type: 'global', key: 'x', value: '3.6.0', version: '3.6.0', confidence: 100, observed: true }] })], 'https://x/a');
    agg.add([det({ version: '1.12.4', evidence: [{ type: 'scriptSrc', value: 'y', version: '1.12.4', confidence: 100, observed: true }] })], 'https://x/b');
    const [tech] = agg.finish();
    expect(tech!.version).toBe('3.6.0');
    expect(tech!.versionConflicts).toContain('1.12.4');
    expect(tech!.versionExact).toBe(false);
  });
});
