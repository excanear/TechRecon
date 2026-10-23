import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { AggregatedTech } from '../src/crawler/aggregate';
import { comparePriority, dedupeFindings, enrichVulns } from '../src/cve/enrich';
import type { EpssResponse } from '../src/cve/epss';
import { parseKevCatalog } from '../src/cve/kev';
import { normalizeNvdResponse, type NvdResponse } from '../src/cve/nvd';
import { buildScanJson, csvCell, escapeHtml, scanFileName, scanToCsv, scanToHtml, scanToMarkdown, type ScanExportInput } from '../src/export/scan';
import type { MisconfigRecord, ScanSession, VulnFindingRecord } from '../src/scan/types';
import { emptyCounters } from '../src/scan/types';

// Real vulnerabilities (recorded NVD responses) enriched with the recorded KEV subset and EPSS response.
const fixture = <T>(name: string): T => JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8')) as T;

async function realFindings(): Promise<VulnFindingRecord[]> {
  const jquery = normalizeNvdResponse([fixture<NvdResponse>('nvd-jquery-3.4.1.json')], ['jquery:jquery'], '3.4.1').vulns;
  const nginx = normalizeNvdResponse([fixture<NvdResponse>('nvd-nginx-1.18.0.json')], ['f5:nginx', 'nginx:nginx'], '1.18.0').vulns;
  const findings = dedupeFindings([
    { techId: 'jquery', techName: 'jQuery', version: '3.4.1', status: 'ok', queries: [], vulns: jquery },
    { techId: 'nginx', techName: 'Nginx', version: '1.18.0', status: 'ok', queries: [], vulns: nginx },
  ]);
  const epss = fixture<EpssResponse>('epss-fixture-cves.json');
  await enrichVulns(
    findings.map((f) => f.vuln),
    {
      fetch: async () => new Response(JSON.stringify(epss), { status: 200 }),
      kev: async () => ({ catalog: parseKevCatalog(fixture('kev-subset.json'), '2026-10-23T00:00:00.000Z'), stale: false }),
    },
  );
  findings.sort((a, b) => comparePriority(a.vuln, b.vuln));
  return findings.map((f, rank) => ({ key: `s1:${f.vuln.id}`, sessionId: 's1', rank, ...f }));
}

const tech = (id: string, name: string, version: string, over: Partial<AggregatedTech> = {}): AggregatedTech => ({
  id,
  name,
  categories: ['js-library'],
  confidence: 100,
  confidenceLevel: 'high',
  version,
  versionExact: true,
  versionConflicts: [],
  inferred: false,
  evidence: [],
  notes: [],
  pageCount: 4,
  samplePages: ['https://shop.example.com/cart?session=abc123'],
  ...over,
});

const misconfig: MisconfigRecord = {
  key: 's1:0',
  sessionId: 's1',
  rank: 0,
  check: 'version-disclosure',
  severity: 'info',
  title: 'Versão divulgada em header',
  detail: 'O header server expõe a versão do software.',
  evidence: 'server: nginx/1.18.0 (Ubuntu)',
  pageCount: 4,
  samplePages: ['https://shop.example.com/'],
};

async function input(): Promise<ScanExportInput> {
  const session: ScanSession = {
    id: 's1',
    label: 'shop.example.com',
    scope: {
      seeds: ['https://shop.example.com/?token=secret-value'],
      includeHosts: [{ pattern: 'shop.example.com' }],
      excludePatterns: [],
      maxDepth: 3,
      maxPages: 100,
      requestsPerSecond: 2,
      concurrency: 2,
      followSubdomains: false,
    },
    authorization: { acknowledged: true, statement: 'Pentest ACME-2026 | escopo assinado', at: '2026-10-23T10:00:00.000Z' },
    status: 'done',
    counters: emptyCounters(),
    createdAt: '2026-10-23T10:00:00.000Z',
    cve: { status: 'done', total: 3, eligible: 2, done: 2, errors: 0 },
    misconfig: { checkedPages: 4 },
  };
  return {
    session,
    toolVersion: '1.0.0',
    generatedAt: new Date('2026-10-23T12:00:00Z'),
    inventory: {
      technologies: [tech('jquery', 'jQuery', '3.4.1'), tech('nginx', 'Nginx', '1.18.0', { categories: ['web-server'] }), tech('php', 'PHP', '', { inferred: true, version: undefined })],
      pages: [
        { key: 's1:1', sessionId: 's1', url: 'https://shop.example.com/?token=secret-value', finalUrl: 'https://shop.example.com/?token=secret-value', depth: 0, status: 200, contentType: 'text/html', technologies: ['jquery'], outlinks: 3, fetchedAt: '' },
      ],
      assets: [{ key: 's1:cdn', sessionId: 's1', host: 'cdn.example.net', count: 4, thirdParty: true }],
      techCve: [
        { key: 's1:jquery', sessionId: 's1', techId: 'jquery', techName: 'jQuery', version: '3.4.1', status: 'ok', queries: [], vulnIds: ['CVE-2020-11022', 'CVE-2020-11023'] },
        { key: 's1:php', sessionId: 's1', techId: 'php', techName: 'PHP', status: 'no-version', message: 'Tecnologia inferida', queries: [], vulnIds: [] },
      ],
      vulnerabilities: await realFindings(),
      misconfigurations: [misconfig],
    },
  };
}

describe('scan JSON export', () => {
  it('is complete, ranked, carries the authorization and redacts URLs', async () => {
    const json = buildScanJson(await input());
    expect(json.schema).toBe('techrecon.scan-report/v1');
    expect(json.session.authorization.statement).toContain('ACME-2026');
    expect(json.session.scope.seeds[0]).toContain('token=REDACTED');
    expect(json.pages[0]!.url).not.toContain('secret-value');
    expect(json.technologies[0]!.samplePages[0]).toContain('session=REDACTED');
    expect(json.vulnerabilities[0]).toMatchObject({ rank: 1, priority: 'kev' });
    expect(json.vulnerabilities.map((v) => v.rank)).toEqual(json.vulnerabilities.map((_, i) => i + 1));
    expect(json.summary).toMatchObject({ pagesFetched: 1, observedTechnologies: 2, knownExploited: 2, configurationFindings: 1, thirdPartyHosts: 1 });
    expect(json.technologies.find((t) => t.id === 'php')!.cveCorrelation).toMatchObject({ status: 'no-version' });
  });
});

describe('scan CSV export', () => {
  it('neutralizes spreadsheet formulas and quotes per RFC 4180', () => {
    expect(csvCell('=HYPERLINK("http://evil","x")')).toBe(`"'=HYPERLINK(""http://evil"",""x"")"`);
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('line\nbreak')).toBe('"line\nbreak"');
    expect(csvCell(7.5)).toBe('7.5');
    expect(csvCell(null)).toBe('');
  });

  it('exports the ranked vulnerabilities with explicit KEV/EPSS states', async () => {
    const out = scanToCsv(await input(), 'vulnerabilities');
    expect(out.startsWith('﻿prioridade,id,')).toBe(true);
    const lines = out.trim().split('\r\n');
    expect(lines).toHaveLength(1 + (await input()).inventory.vulnerabilities.length);
    expect(lines[1]).toMatch(/^1,CVE-/);
    expect(out).toContain('CVE-2020-11023');
    expect(out).toMatch(/sim \(2025-01-23\)/);
  });

  it('exports every table', async () => {
    const i = await input();
    expect(scanToCsv(i, 'technologies')).toContain('jQuery,3.4.1,sim');
    expect(scanToCsv(i, 'pages')).toContain('token=REDACTED');
    expect(scanToCsv(i, 'configuration')).toContain('server: nginx/1.18.0 (Ubuntu)');
  });
});

describe('scan Markdown export', () => {
  it('escapes table cells and states exploitation', async () => {
    const md = scanToMarkdown(await input());
    expect(md).toContain('# TechRecon — varredura shop.example.com');
    expect(md).toContain('Pentest ACME-2026 \\| escopo assinado');
    expect(md).toContain('| 1 | [CVE-');
    expect(md).toMatch(/KEV/);
    expect(md).toContain('## Configuração (passiva)');
    expect(md).not.toContain('secret-value');
  });
});

describe('scan HTML export', () => {
  it('is static, escaped and safe to open', async () => {
    const i = await input();
    i.session.label = '<img src=x onerror=alert(1)>';
    i.inventory.vulnerabilities[0]!.vuln.title = '<script>alert(1)</script>';
    i.inventory.vulnerabilities[0]!.vuln.sourceUrl = 'javascript:alert(1)';
    const html = scanToHtml(i);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain(`content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"`);
    expect(html).not.toContain('secret-value');
    expect(html).toContain('class="kev"');
  });

  it('escapes the five HTML-significant characters', () => {
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
  });
});

describe('scanFileName', () => {
  it('builds a safe, dated name', async () => {
    const { session } = await input();
    expect(scanFileName(session, 'csv', 'vulnerabilities', new Date('2026-10-23T12:00:00Z'))).toBe('techrecon-scan-shop.example.com-vulnerabilities-2026-10-23T12-00-00.csv');
  });
});
