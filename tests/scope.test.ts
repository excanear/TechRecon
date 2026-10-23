import { describe, expect, it } from 'vitest';
import { classifyLink, crawlableLinks } from '../src/crawler/links';
import { ConcurrencyLimiter, HostRateLimiter } from '../src/scope/limits';
import { decideScope, globToRegExp, hostMatches, isInScope, normalizeUrl, sanitizeScope, scopeFromSeeds } from '../src/scope/scope';
import type { ScopeConfig } from '../src/scan/types';

describe('url normalization', () => {
  it('drops fragments, default ports, credentials and lowercases the host', () => {
    expect(normalizeUrl('HTTPS://User:Pw@Example.COM:443/a?b=1#frag')).toBe('https://example.com/a?b=1');
    expect(normalizeUrl('http://example.com:80/')).toBe('http://example.com/');
    expect(normalizeUrl('/path', 'https://example.com/base/')).toBe('https://example.com/path');
    expect(normalizeUrl('ftp://example.com')).toBeNull();
    expect(normalizeUrl('not a url')).toBeNull();
  });
});

describe('host matching', () => {
  it('matches exact hosts', () => {
    expect(hostMatches('example.com', { pattern: 'example.com' })).toBe(true);
    expect(hostMatches('www.example.com', { pattern: 'example.com' })).toBe(false);
  });
  it('wildcard matches apex and subdomains', () => {
    expect(hostMatches('example.com', { pattern: '*.example.com' })).toBe(true);
    expect(hostMatches('a.b.example.com', { pattern: '*.example.com' })).toBe(true);
    expect(hostMatches('notexample.com', { pattern: '*.example.com' })).toBe(false);
    expect(hostMatches('example.com.evil.com', { pattern: '*.example.com' })).toBe(false);
  });
});

describe('glob exclusion', () => {
  it('only treats * as special and anchors the match', () => {
    expect(globToRegExp('*/admin/*').test('https://x.com/a/admin/b')).toBe(true);
    expect(globToRegExp('*/admin/*').test('https://x.com/administrator')).toBe(false);
    expect(globToRegExp('*.pdf').test('https://x.com/a.pdf')).toBe(true);
    expect(globToRegExp('https://x.com/exact').test('https://x.com/exact?q=1')).toBe(false);
  });
});

describe('scope decisions', () => {
  const scope: ScopeConfig = {
    seeds: ['https://example.com/'],
    includeHosts: [{ pattern: 'example.com' }, { pattern: '*.example.com' }],
    excludePatterns: ['*/logout*', '*/private/*'],
    maxDepth: 3,
    maxPages: 100,
    requestsPerSecond: 2,
    concurrency: 3,
    followSubdomains: true,
  };

  it('accepts in-scope hosts and rejects others', () => {
    expect(decideScope('https://example.com/a', scope)).toMatchObject({ inScope: true });
    expect(decideScope('https://api.example.com/a', scope)).toMatchObject({ inScope: true });
    expect(decideScope('https://evil.com/a', scope)).toMatchObject({ inScope: false, reason: 'host-not-included' });
  });

  it('respects exclude patterns', () => {
    expect(decideScope('https://example.com/private/x', scope).reason).toBe('excluded');
    expect(decideScope('https://example.com/logout', scope).reason).toBe('excluded');
  });

  it('rejects non-http protocols', () => {
    expect(decideScope('javascript:alert(1)', scope).reason).toBe('bad-url');
  });

  it('blocks subdomains when followSubdomains is off', () => {
    const narrow = { ...scope, followSubdomains: false };
    expect(isInScope('https://example.com/a', narrow)).toBe(true);
    expect(decideScope('https://api.example.com/a', narrow).reason).toBe('subdomain-blocked');
  });
});

describe('scope construction and sanitization', () => {
  it('builds a default scope from seeds', () => {
    const scope = scopeFromSeeds(['https://example.com/start', 'https://example.com/other']);
    expect(scope.includeHosts).toEqual([{ pattern: 'example.com' }]);
    expect(scope.followSubdomains).toBe(false);
    expect(scope.maxPages).toBeGreaterThan(0);
  });

  it('clamps dangerous limits to safe ranges', () => {
    const s = sanitizeScope({
      seeds: ['https://example.com/'],
      includeHosts: [{ pattern: 'example.com' }],
      excludePatterns: [],
      maxDepth: 999,
      maxPages: 10_000_000,
      requestsPerSecond: 10_000,
      concurrency: 500,
      followSubdomains: true,
    });
    expect(s.maxDepth).toBeLessThanOrEqual(12);
    expect(s.maxPages).toBeLessThanOrEqual(5000);
    expect(s.requestsPerSecond).toBeLessThanOrEqual(20);
    expect(s.concurrency).toBeLessThanOrEqual(10);
  });
});

describe('link classifier (non-destructive guard-rail)', () => {
  const base = 'https://example.com/page';

  it('crawls ordinary in-document links', () => {
    expect(classifyLink('/about', base)).toEqual({ crawl: true, url: 'https://example.com/about' });
    expect(classifyLink('products?id=5', base)).toMatchObject({ crawl: true });
  });

  it.each([
    ['/logout', 'auth-transition'],
    ['/account/signout', 'auth-transition'],
    ['/posts/42/delete', 'destructive-path'],
    ['/users/remove', 'destructive-path'],
    ['/report.pdf', 'non-document'],
    ['/app.js', 'non-document'],
    ['/download/file.zip', 'non-document'],
    ['mailto:x@y.com', 'non-http'],
    ['javascript:void(0)', 'non-http'],
    ['tel:+5511', 'non-http'],
  ])('refuses %s (%s)', (href, reason) => {
    expect(classifyLink(href, base)).toMatchObject({ crawl: false, reason });
  });

  it('refuses state-changing query params even on normal paths', () => {
    expect(classifyLink('/post?action=delete&id=1', base).crawl).toBe(false);
    expect(classifyLink('/x?_wpnonce=abc', base)).toMatchObject({ crawl: false, reason: 'state-changing-query' });
    expect(classifyLink('/comment?do=remove', base).crawl).toBe(false);
  });

  it('dedupes and normalizes a batch of hrefs', () => {
    const links = crawlableLinks(['/a#x', '/a', '/logout', 'https://example.com/a', '/b'], base);
    expect(links.sort()).toEqual(['https://example.com/a', 'https://example.com/b']);
  });
});

describe('rate and concurrency limits', () => {
  it('spaces requests per host by the configured interval', async () => {
    let clock = 0;
    const sleeps: number[] = [];
    const sleep = async (ms: number) => {
      sleeps.push(ms);
      clock += ms;
    };
    const limiter = new HostRateLimiter(2, sleep, () => clock); // 500ms interval
    await limiter.acquire('a.com');
    await limiter.acquire('a.com');
    await limiter.acquire('a.com');
    expect(sleeps).toEqual([500, 500]);
  });

  it('never runs more than the concurrency cap at once', async () => {
    const limiter = new ConcurrencyLimiter(2);
    let active = 0;
    let peak = 0;
    const task = () =>
      limiter.run(async () => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
      });
    await Promise.all(Array.from({ length: 8 }, task));
    expect(peak).toBe(2);
    expect(limiter.inFlight).toBe(0);
  });

  it('releases the slot even when the task throws', async () => {
    const limiter = new ConcurrencyLimiter(1);
    await expect(limiter.run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(limiter.inFlight).toBe(0);
    await expect(limiter.run(async () => 'ok')).resolves.toBe('ok');
  });
});
