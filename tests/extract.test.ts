import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';
import { extractFromDocument } from '../src/offscreen/extract';
import { detectTechnologies } from '../src/fingerprinting/engine';

function parse(html: string): Document {
  return new JSDOM(html).window.document;
}

describe('offscreen extraction', () => {
  const html = `<!doctype html><html><head>
    <meta name="generator" content="WordPress 6.4.2">
    <link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">
    <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
    <script>window.foo = 1;</script>
    <base href="https://example.com/app/">
  </head><body>
    <a href="page2">rel</a>
    <a href="/abs">abs</a>
    <a href="https://other.com/x">ext</a>
    <a href="logout">out</a>
  </body></html>`;

  it('builds a snapshot with absolute script/style URLs, meta and response headers', () => {
    const { snapshot } = extractFromDocument(parse(html), 'https://example.com/', { server: 'nginx/1.18.0', 'set-cookie': 'secret=1' });
    expect(snapshot.scriptSrcs).toContain('https://code.jquery.com/jquery-3.4.1.min.js');
    expect(snapshot.stylesheets[0]).toBe('https://example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2');
    expect(snapshot.meta.generator).toEqual(['WordPress 6.4.2']);
    expect(snapshot.inlineScripts).toContain('window.foo');
    expect(snapshot.headers?.server).toBe('nginx/1.18.0');
    // Set-Cookie must never survive into the snapshot.
    expect(snapshot.headers?.['set-cookie']).toBe('[redacted]');
  });

  it('resolves links against <base> and returns raw hrefs (classification happens in the crawler)', () => {
    const { links } = extractFromDocument(parse(html), 'https://example.com/', {});
    expect(links).toContain('https://example.com/app/page2');
    expect(links).toContain('https://example.com/abs');
    expect(links).toContain('https://other.com/x');
  });

  it('feeds straight into the detection engine (headers now available per page)', () => {
    const { snapshot } = extractFromDocument(parse(html), 'https://example.com/', { server: 'nginx/1.18.0 (Ubuntu)' });
    const ids = detectTechnologies(snapshot).map((d) => d.id);
    expect(ids).toContain('wordpress');
    expect(ids).toContain('jquery');
    expect(ids).toContain('nginx');
  });
});
