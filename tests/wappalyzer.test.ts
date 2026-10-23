import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { detectTechnologies } from '../src/fingerprinting/engine';
import type { Signature } from '../src/fingerprinting/signature';
import { SIGNATURES } from '../src/fingerprinting/signatures';
import { convertWappalyzer, cookieNamePattern, parsePattern, WAPPALYZER_CONFIDENCE_WEIGHT, type RawTechnology } from '../src/fingerprinting/wappalyzer/convert';
import { DATASET_FILES, downloadDataset, WAPPALYZER_COMMIT } from '../src/fingerprinting/wappalyzer/dataset';
import type { PageSnapshot } from '../src/types';

// Verbatim upstream entries (see tests/fixtures/wappalyzer/README.md).
const FIXTURE_PATH = new URL('./fixtures/wappalyzer/technologies.json', import.meta.url);
const FIXTURE_BYTES = readFileSync(FIXTURE_PATH);
const RAW = JSON.parse(FIXTURE_BYTES.toString('utf8')) as Record<string, RawTechnology>;

function snapshot(over: Partial<PageSnapshot> = {}): PageSnapshot {
  return { url: 'https://example.com/', html: '', scriptSrcs: [], inlineScripts: '', stylesheets: [], meta: {}, cookieNames: [], headers: null, globals: {}, dom: {}, resources: [], ...over };
}

function converted() {
  const result = convertWappalyzer(RAW, SIGNATURES);
  const byName = new Map(result.signatures.map((s) => [s.name, s]));
  return { ...result, byName, all: [...SIGNATURES, ...result.signatures] as Signature[] };
}

describe('parsePattern', () => {
  it('splits the regex from version and confidence tags and rewrites back-references', () => {
    const p = parsePattern(RAW['Elementor']!.meta!['generator'] as string)!;
    expect(p.pattern.source).toBe('^Elementor\\s([\\d\\.]+)');
    expect(p.pattern.flags).toBe('i');
    expect(p.version).toBe('$1');
    expect(p.confidence).toBe(100);
  });

  it('keeps the conditional version form', () => {
    const scripts = RAW['Google Analytics']!.scripts as string[];
    expect(parsePattern(scripts[1]!)!.version).toBe('$1?GA4:');
  });

  it('rejects patterns that do not compile', () => {
    expect(parsePattern('([unclosed')).toBeNull();
  });
});

describe('cookieNamePattern', () => {
  it('handles literal names, trailing wildcards and PHP-style brackets', () => {
    expect(cookieNamePattern('_ga_*')!.test('_ga_ABC123')).toBe(true);
    expect(cookieNamePattern('_ga')!.test('_ga_ABC123')).toBe(false);
    expect(cookieNamePattern('mybb[lastvisit]')!.test('mybb[lastvisit]')).toBe(true);
    expect(cookieNamePattern('SESS[a-f0-9]{32}')!.test(`SESS${'a'.repeat(32)}`)).toBe(true);
    expect(cookieNamePattern('(?i)ltpatoken')!.test('LtpaToken')).toBe(true);
  });
});

describe('convertWappalyzer', () => {
  it('gives curated signatures precedence and redirects references to them', () => {
    const { byName, stats } = converted();
    // WordPress, Nuxt.js (alias), Google Analytics and PHP are curated: their entries are dropped.
    for (const name of ['WordPress', 'Nuxt.js', 'Google Analytics', 'PHP']) expect(byName.has(name)).toBe(false);
    expect(stats.curatedOverlap).toBeGreaterThanOrEqual(4);
    expect(byName.get('Elementor')!.requires).toEqual(['wordpress']);
    expect(byName.get('Yoast SEO')!.implies).toEqual(['wordpress']);
  });

  it('marks provenance, maps categories and CPE, and weights confidence', () => {
    const { byName } = converted();
    const mysql = byName.get('MySQL')!;
    expect(mysql.id).toBe('wa-mysql');
    expect(mysql.source).toBe('wappalyzer');
    expect(mysql.categories).toEqual(['database']);
    expect(mysql.cpe).toEqual(['mysql:mysql']);
    expect(byName.get('Elementor')!.categories).toEqual(['cms', 'cms-extension']);
    expect(byName.get('Yoast SEO')!.categories).toEqual(['marketing', 'cms-extension']);
    expect(byName.get('Elementor')!.rules.globals!['elementorModules']![0]!.confidence).toBe(100 * WAPPALYZER_CONFIDENCE_WEIGHT);
  });

  it('resolves exclusions to curated ids', () => {
    const curatedIds = ['Angular', 'AngularJS'].map((n) => SIGNATURES.find((s) => s.name === n)!.id);
    expect(converted().byName.get('AngularDart')!.excludes).toEqual(curatedIds);
  });

  it('turns DOM attribute specs into attribute rules with versions', () => {
    const dom = converted().byName.get('Ant Design')!.rules.dom!;
    expect(dom).toHaveLength(2);
    expect(dom[1]).toMatchObject({ selector: "link[href*='antd']", attribute: 'href', rule: { version: '$1' } });
  });

  it('keeps requiresCategory, mapped to TechRecon categories', () => {
    expect(converted().byName.get('Afterpay')!.requiresCategories).toEqual(['ecommerce']);
  });

  it('skips malformed entries and patterns instead of guessing', () => {
    const { signatures, stats } = convertWappalyzer(
      { Broken: { cats: [12], html: ['([bad', 'ok-marker'], js: { x: 42 as unknown as string } }, Junk: 'nope' as unknown as RawTechnology },
      SIGNATURES,
    );
    expect(stats.invalidPatterns).toBe(1);
    expect(signatures).toHaveLength(1);
    expect(signatures[0]!.rules.html).toHaveLength(1);
    expect(signatures[0]!.rules.globals).toBeUndefined();
  });
});

describe('engine with converted signatures', () => {
  it('detects a WordPress plugin with its version, tagged as Wappalyzer, alongside curated WordPress', () => {
    const { all } = converted();
    const page = snapshot({
      meta: { generator: ['WordPress 6.6.2', 'Elementor 3.24.7'] },
      scriptSrcs: ['https://example.com/wp-content/plugins/elementor/assets/js/frontend-modules.min.js?ver=3.24.7'],
    });
    const dets = detectTechnologies(page, all);
    const elementor = dets.find((d) => d.name === 'Elementor')!;
    expect(elementor.source).toBe('wappalyzer');
    expect(elementor.version).toBe('3.24.7');
    expect(elementor.versionExact).toBe(true);
    const wordpress = dets.find((d) => d.id === 'wordpress')!;
    expect(wordpress.source).toBeUndefined();
    expect(wordpress.version).toBe('6.6.2');
  });

  it('drops a technology whose requirement is absent', () => {
    const { all } = converted();
    const page = snapshot({ meta: { generator: ['Elementor 3.24.7'] } });
    expect(detectTechnologies(page, all).find((d) => d.name === 'Elementor')).toBeUndefined();
  });

  it('accepts a requirement satisfied only by inference', () => {
    const { all } = converted();
    // Yoast implies WordPress; Elementor requires WordPress. Nothing else points to WordPress.
    const page = snapshot({
      html: '<!-- This site is optimized with the Yoast SEO plugin v23.5 - https://yoast.com/wordpress/plugins/seo/ -->',
      meta: { generator: ['Elementor 3.24.7'] },
    });
    const dets = detectTechnologies(page, all);
    expect(dets.find((d) => d.name === 'Yoast SEO')!.version).toBe('23.5');
    expect(dets.find((d) => d.name === 'Elementor')).toBeDefined();
    expect(dets.find((d) => d.id === 'wordpress')!.inferred).toBe(true);
  });

  it('applies requiresCategory', () => {
    const { all } = converted();
    const afterpay = RAW['Afterpay']!;
    const src = (afterpay.scriptSrc as string[])[0]!.split('\\;')[0]!.replace(/\\/g, '');
    const page = snapshot({ scriptSrcs: [`https://${src}`] });
    // No e-commerce platform on the page: the payment widget is not reported.
    expect(detectTechnologies(page, all).find((d) => d.name === 'Afterpay')).toBeUndefined();
  });

  it('resolves conditional versions', () => {
    const rule = parsePattern((RAW['Google Analytics']!.scripts as string[])[1]!)!;
    const sig: Signature = { id: 'x', name: 'X', categories: ['analytics'], rules: { script: [{ ...rule, version: '$1?4.1:' }] } };
    const det = detectTechnologies(snapshot({ inlineScripts: "gtag('config', 'G-ABC123');" }), [sig])[0]!;
    expect(det.version).toBe('4.1');
  });
});

describe('downloadDataset', () => {
  const files = { 'technologies/a.json': createHash('sha256').update(FIXTURE_BYTES).digest('hex') };
  const ok = () => vi.fn(async () => new Response(FIXTURE_BYTES, { status: 200 }));

  it('pins every technology file of the upstream commit', () => {
    expect(WAPPALYZER_COMMIT).toMatch(/^[0-9a-f]{40}$/);
    expect(Object.keys(DATASET_FILES)).toHaveLength(27);
    for (const digest of Object.values(DATASET_FILES)) expect(digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('downloads from the pinned commit, verifies and keeps only the fields it uses', async () => {
    const fetchFn = ok();
    const progress: number[] = [];
    const dataset = await downloadDataset(fetchFn, { files, onProgress: (d) => progress.push(d), now: () => new Date('2026-10-23T00:00:00Z') });
    expect(fetchFn).toHaveBeenCalledWith(expect.stringContaining(`/enthec/webappanalyzer/${WAPPALYZER_COMMIT}/src/technologies/a.json`), expect.objectContaining({ credentials: 'omit' }));
    expect(Object.keys(dataset.technologies)).toHaveLength(Object.keys(RAW).length);
    expect(dataset.technologies['Angular']).not.toHaveProperty('description');
    expect(dataset.technologies['Angular']).toHaveProperty('dom');
    expect(dataset.fetchedAt).toBe('2026-10-23T00:00:00.000Z');
    expect(progress).toEqual([1]);
  });

  it('refuses a file whose digest does not match', async () => {
    const tampered = vi.fn(async () => new Response(Buffer.concat([FIXTURE_BYTES, Buffer.from(' ')]), { status: 200 }));
    await expect(downloadDataset(tampered, { files })).rejects.toThrow(/Integridade inválida em technologies\/a\.json/);
  });

  it('reports HTTP and network failures', async () => {
    await expect(downloadDataset(vi.fn(async () => new Response('', { status: 404 })), { files })).rejects.toThrow(/HTTP 404/);
    await expect(downloadDataset(vi.fn(async () => Promise.reject(new TypeError('offline'))), { files })).rejects.toThrow(/Falha de rede.*offline/);
  });
});
