import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import type { FetchedPage } from '../src/crawler/types';
import { MisconfigAggregator } from '../src/misconfig/aggregate';
import { checkPage, type MisconfigCheckId } from '../src/misconfig/checks';
import { extractFromDocument } from '../src/offscreen/extract';

const HARDENED = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
};

/** A crawled page built the way the offscreen document builds it: real HTML through the extractor. */
function crawled(url: string, html: string, headers: Record<string, string> = {}, over: Partial<FetchedPage> = {}): FetchedPage {
  const { snapshot, links, scriptsWithoutIntegrity } = extractFromDocument(new JSDOM(html, { url }).window.document, url, headers);
  return { requestedUrl: url, finalUrl: url, ok: true, status: 200, contentType: 'text/html', headers, links, snapshot, scriptsWithoutIntegrity, bytes: html.length, ...over };
}

/** Headers as the crawl delivers them: an absent header is a missing key, never undefined. */
function without(headers: Record<string, string>, name: string): Record<string, string> {
  const { [name]: _drop, ...rest } = headers;
  return rest;
}

const ids = (page: FetchedPage): MisconfigCheckId[] => checkPage(page).map((o) => o.check).sort();

describe('extraction for SRI', () => {
  it('lists external scripts without an integrity attribute', () => {
    const page = crawled(
      'https://shop.example.com/',
      `<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js" integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs" crossorigin="anonymous"></script>
       <script src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>
       <script src="/static/app.js"></script>`,
    );
    expect(page.scriptsWithoutIntegrity).toEqual(['https://www.googletagmanager.com/gtag/js?id=G-X', 'https://shop.example.com/static/app.js']);
  });
});

describe('checkPage', () => {
  it('reports nothing on a hardened HTTPS page', () => {
    expect(ids(crawled('https://example.com/', '<p>ok</p>', HARDENED))).toEqual([]);
  });

  it('flags missing headers on HTTPS', () => {
    expect(ids(crawled('https://example.com/', '<p>x</p>', {}))).toEqual(['csp-missing', 'framing-unprotected', 'hsts-missing', 'nosniff-missing']);
  });

  it('does not ask an HTTP page for HSTS, but flags the page itself', () => {
    const found = ids(crawled('http://example.com/', '<p>x</p>', without(HARDENED, 'strict-transport-security')));
    expect(found).toContain('http-page');
    expect(found).not.toContain('hsts-missing');
  });

  it('analyses weak HSTS and permissive CSP, keeping the header as evidence', () => {
    const page = crawled('https://example.com/', '', {
      ...HARDENED,
      'strict-transport-security': 'max-age=300',
      'content-security-policy': "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'",
    });
    const byId = Object.fromEntries(checkPage(page).map((o) => [o.check, o]));
    expect(byId['hsts-weak']!.detail).toMatch(/max-age baixo/);
    expect(byId['csp-weak']!.detail).toMatch(/unsafe-inline/);
    expect(byId['csp-weak']!.evidence).toContain('unsafe-eval');
    expect(byId['framing-unprotected']).toBeUndefined();
  });

  it('accepts a CSP meta tag for script policy but not for framing', () => {
    const page = crawled('https://example.com/', `<meta http-equiv="Content-Security-Policy" content="script-src 'self'; object-src 'none'; frame-ancestors 'none'">`, {
      'strict-transport-security': HARDENED['strict-transport-security'],
      'x-content-type-options': 'nosniff',
    });
    const found = ids(page);
    expect(found).not.toContain('csp-missing');
    expect(found).toContain('framing-unprotected');
  });

  it('reports versioned server banners only', () => {
    const versioned = checkPage(crawled('https://example.com/', '', { ...HARDENED, server: 'nginx/1.18.0 (Ubuntu)', 'x-powered-by': 'PHP/7.4.3' }));
    expect(versioned.filter((o) => o.check === 'version-disclosure').map((o) => o.evidence)).toEqual(['server: nginx/1.18.0 (Ubuntu)', 'x-powered-by: PHP/7.4.3']);
    expect(ids(crawled('https://example.com/', '', { ...HARDENED, server: 'cloudflare' }))).toEqual([]);
  });

  it('distinguishes open CORS from wildcard with credentials', () => {
    expect(ids(crawled('https://example.com/', '', { ...HARDENED, 'access-control-allow-origin': '*' }))).toEqual(['cors-wildcard']);
    const both = checkPage(crawled('https://example.com/', '', { ...HARDENED, 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }));
    expect(both.map((o) => [o.check, o.severity])).toEqual([['cors-wildcard-credentials', 'medium']]);
  });

  it('finds mixed content and third-party scripts without SRI', () => {
    const page = crawled(
      'https://www.example.com/',
      `<script src="http://cdn.example.net/legacy.js"></script>
       <link rel="stylesheet" href="http://fonts.example.net/a.css">
       <script src="https://static.example.com/own.js"></script>`,
      HARDENED,
    );
    const byId = Object.fromEntries(checkPage(page).map((o) => [o.check, o]));
    expect(byId['mixed-content-script']).toMatchObject({ severity: 'high', evidence: 'http://cdn.example.net/legacy.js' });
    expect(byId['mixed-content-style']!.severity).toBe('medium');
    // static.example.com is the same site as www.example.com: only the third-party script counts.
    expect(byId['sri-missing']!.evidence).toBe('http://cdn.example.net/legacy.js');
  });

  it('skips pages that were not fetched successfully', () => {
    expect(checkPage(crawled('https://example.com/x', '', {}, { ok: false, status: 404 }))).toEqual([]);
    expect(checkPage(crawled('https://example.com/f.pdf', '', {}, { skippedReason: 'not-html' }))).toEqual([]);
  });
});

describe('MisconfigAggregator', () => {
  it('merges per check across pages, separates distinct banners, and sorts by severity', () => {
    const agg = new MisconfigAggregator();
    const headers = without(HARDENED, 'content-security-policy');
    for (let i = 0; i < 7; i++) {
      const url = `https://example.com/p${i}?session=abc`;
      agg.add(checkPage(crawled(url, i === 0 ? '<script src="http://x.example.net/a.js"></script>' : '', { ...headers, server: i < 2 ? 'Apache/2.4.41' : 'Apache/2.4.58' })), url);
    }
    const findings = agg.finish();
    expect(agg.checkedPages).toBe(7);
    expect(findings[0]).toMatchObject({ check: 'mixed-content-script', pageCount: 1 });
    expect(findings.find((f) => f.check === 'csp-missing')).toMatchObject({ pageCount: 7 });
    expect(findings.find((f) => f.check === 'csp-missing')!.samplePages).toHaveLength(5);
    expect(findings.find((f) => f.check === 'csp-missing')!.samplePages[0]).toContain('session=REDACTED');
    expect(findings.filter((f) => f.check === 'version-disclosure').map((f) => f.pageCount)).toEqual([5, 2]);
  });
});
