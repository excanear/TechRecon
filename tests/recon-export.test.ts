import { describe, expect, it } from 'vitest';
import { buildJsonReport, mdCell, toJson, toMarkdown, reportFileName } from '../src/export';
import { buildRecon, siteOf } from '../src/recon';
import { redactHeaders, redactUrl } from '../src/shared/redact';
import { safeHttpUrl, safeIdentifier, sanitizeText } from '../src/shared/sanitize';
import type { AnalysisState, CollectedDom } from '../src/types';

function dom(overrides: Partial<CollectedDom> = {}): CollectedDom {
  return {
    url: 'https://shop.example.co.uk/page',
    title: 'Test',
    html: '<html></html>',
    htmlTruncated: false,
    scripts: [],
    inlineScripts: '',
    inlineScriptCount: 0,
    stylesheets: [],
    meta: {},
    cookieNames: [],
    cookieValueLengths: {},
    resources: [],
    dom: {},
    protocol: 'https:',
    contentType: 'text/html',
    characterSet: 'UTF-8',
    ...overrides,
  };
}

describe('recon', () => {
  it('does not claim headers are absent when they were not observed', () => {
    const recon = buildRecon(dom(), null);
    expect(recon.headerSource).toBe('none');
    expect(recon.securityHeaders.every((h) => h.state === 'not-observed')).toBe(true);
    expect(recon.notes.join(' ')).toMatch(/não observados/);
  });

  it('uses a meta CSP when present, noting its limitations', () => {
    const recon = buildRecon(dom({ meta: { 'content-security-policy': ["default-src 'self'; script-src 'self' 'unsafe-inline'"] } }), null);
    const csp = recon.securityHeaders.find((h) => h.id === 'content-security-policy')!;
    expect(csp).toMatchObject({ state: 'present', origin: 'meta' });
    expect(csp.notes.join(' ')).toMatch(/unsafe-inline/);
    expect(csp.notes.join(' ')).toMatch(/frame-ancestors/);
  });

  it('evaluates probed headers and flags version disclosure', () => {
    const recon = buildRecon(dom(), {
      status: 200,
      url: 'https://shop.example.co.uk/page',
      fetchedAt: '2026-01-01T00:00:00Z',
      headers: { 'strict-transport-security': 'max-age=300', server: 'nginx/1.18.0', 'x-content-type-options': 'nosniff', 'set-cookie': 'a=b' },
    });
    const hsts = recon.securityHeaders.find((h) => h.id === 'strict-transport-security')!;
    expect(hsts.state).toBe('present');
    expect(hsts.notes.join(' ')).toMatch(/max-age baixo/);
    expect(recon.securityHeaders.find((h) => h.id === 'x-frame-options')!.state).toBe('absent');
    expect(recon.notes.join(' ')).toMatch(/server divulga versão/);
    expect(recon.headers['set-cookie']).toBe('[redacted]');
  });

  it('inventories scripts with first/third party, SRI and mixed content', () => {
    const recon = buildRecon(
      dom({
        scripts: [
          { src: 'https://cdn.example.co.uk/app.js', integrity: false, crossorigin: null, async: false, defer: true, module: false },
          { src: 'https://cdnjs.cloudflare.com/x.js', integrity: true, crossorigin: 'anonymous', async: true, defer: false, module: false },
          { src: 'http://tracker.test/t.js', integrity: false, crossorigin: null, async: false, defer: false, module: false },
        ],
      }),
      null,
    );
    expect(recon.scripts.map((s) => s.thirdParty)).toEqual([false, true, true]);
    expect(recon.scripts[2]!.insecure).toBe(true);
    expect(recon.mixedContent).toEqual(['http://tracker.test/t.js']);
    expect(recon.notes.join(' ')).toMatch(/1 script\(s\) de terceiros sem Subresource Integrity/);
  });

  it('groups sites with common multi-label suffixes', () => {
    expect(siteOf('a.b.example.co.uk')).toBe('example.co.uk');
    expect(siteOf('www.example.com.br')).toBe('example.com.br');
    expect(siteOf('cdn.example.com')).toBe('example.com');
    expect(siteOf('10.0.0.1')).toBe('10.0.0.1');
  });
});

const state: AnalysisState = {
  tabId: 1,
  url: 'https://example.com/?token=abcdef123456',
  domain: 'example.com',
  status: 'done',
  startedAt: '2026-10-22T10:00:00.000Z',
  finishedAt: '2026-10-22T10:00:05.000Z',
  cveLookupEnabled: true,
  recon: null,
  technologies: [
    {
      id: 'jquery',
      name: 'jQuery',
      categories: ['js-library'],
      confidence: 100,
      confidenceLevel: 'high',
      version: '3.4.1',
      versionExact: true,
      versionConflicts: [],
      inferred: false,
      evidence: [{ type: 'global', key: 'jQuery.fn.jquery', value: '3.4.1', version: '3.4.1', confidence: 100, observed: true }],
      notes: [],
      npm: 'jquery',
    },
  ],
  vulnReports: {
    jquery: {
      techId: 'jquery',
      techName: 'jQuery',
      version: '3.4.1',
      status: 'ok',
      queries: [{ source: 'osv', query: 'npm/jquery@3.4.1', ok: true, cached: false, discarded: 0 }],
      vulns: [
        {
          id: 'CVE-2020-11022',
          aliases: ['GHSA-gxr4-xjj5-5px2'],
          title: 'Potential XSS | vulnerability in jQuery',
          description: '',
          cvss: { version: '3.1', score: 6.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N', severity: 'MEDIUM' },
          severity: 'MEDIUM',
          affected: ['>= 1.12.0, < 3.5.0'],
          fixedIn: '3.5.0',
          matchBasis: 'Versão 3.4.1 dentro de >= 1.12.0, < 3.5.0 (npm/jquery)',
          source: 'osv',
          sourceUrl: 'https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2',
          references: [{ url: 'https://github.com/advisories/GHSA-gxr4-xjj5-5px2', label: 'GitHub Advisory' }],
        },
      ],
    },
  },
};

describe('export', () => {
  const meta = { toolVersion: '1.0.0', generatedAt: new Date('2026-10-22T10:01:00Z') };

  it('JSON contains domain, dates, technologies, evidence, CVEs and references', () => {
    const report = buildJsonReport(state, {}, meta);
    expect(report.target.domain).toBe('example.com');
    expect(report.target.url).toContain('token=REDACTED');
    expect(report.technologies[0]).toMatchObject({ name: 'jQuery', version: '3.4.1', confidence: 100 });
    expect(report.technologies[0]!.evidence).toHaveLength(1);
    expect(report.vulnerabilities[0]).toMatchObject({ id: 'CVE-2020-11022', status: 'potential', fixedIn: '3.5.0' });
    expect(report.summary).toMatchObject({ potentialVulnerabilities: 1, confirmedByAnalyst: 0 });
    expect(JSON.parse(toJson(state, {}, meta)).schema).toBe('techrecon.report/v1');
  });

  it('distinguishes analyst-confirmed findings', () => {
    const report = buildJsonReport(state, { 'CVE-2020-11022': { at: '2026-10-22T11:00:00Z', techId: 'jquery' } }, meta);
    expect(report.vulnerabilities[0]!.status).toBe('confirmed-by-analyst');
    expect(report.summary.confirmedByAnalyst).toBe(1);
  });

  it('Markdown escapes table-breaking characters and links to official sources', () => {
    const md = toMarkdown(state, {}, meta);
    expect(md).toContain('# TechRecon — example.com');
    expect(md).toContain('Potential XSS \\| vulnerability');
    expect(md).toContain('[CVE-2020-11022](https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2)');
    expect(md).toContain('Potencial');
    expect(mdCell('a|b\n<c>')).toBe('a\\|b \\<c\\>');
  });

  it('builds safe file names', () => {
    expect(reportFileName(state, 'md', new Date('2026-10-22T10:01:02.123Z'))).toBe('techrecon-example.com-2026-10-22T10-01-02.md');
  });
});

describe('sanitization and redaction', () => {
  it('only allows http(s) links', () => {
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull();
    expect(safeHttpUrl('data:text/html,x')).toBeNull();
    expect(safeHttpUrl('https://user:pw@example.com')).toBeNull();
    expect(safeHttpUrl('https://nvd.nist.gov/vuln/detail/CVE-2020-11022')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2020-11022');
  });

  it('validates identifiers and strips control characters', () => {
    expect(safeIdentifier('CVE-2020-11022')).toBe('CVE-2020-11022');
    expect(safeIdentifier('<img src=x>')).toBeNull();
    expect(sanitizeText('a\u0000b‮c   d')).toBe('abc d');
    expect(sanitizeText('x'.repeat(20), 10)).toHaveLength(10);
  });

  it('redacts secrets from URLs and headers but keeps version evidence', () => {
    expect(redactUrl('https://maps.googleapis.com/maps/api/js?key=AIzaSyA1234567890&ver=3.2')).toBe(
      'https://maps.googleapis.com/maps/api/js?key=REDACTED&ver=3.2',
    );
    expect(redactUrl('https://x.test/a.js?access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def')).toContain('access_token=REDACTED');
    expect(redactHeaders({ authorization: 'Bearer x', 'x-csrf-token': 'y', server: 'nginx' })).toEqual({
      authorization: '[redacted]',
      'x-csrf-token': '[redacted]',
      server: 'nginx',
    });
  });
});
