import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildMatchString, evaluateNvdConfigurations, parseCpe } from '../src/cve/cpe';
import { cvss3BaseScore, roundUp, severityFromScore } from '../src/cve/cvss';
import { normalizeNvdResponse, nvdQueryUrl, pickCvss, titleFromDescription, type NvdResponse } from '../src/cve/nvd';
import { evaluateOsvAffected, normalizeOsvResponse, type OsvResponse } from '../src/cve/osv';

// Fixtures are real API responses recorded from services.nvd.nist.gov and api.osv.dev.
const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8')) as T;

describe('CPE parsing', () => {
  it('splits on unescaped colons only', () => {
    const cpe = parseCpe('cpe:2.3:o:siemens:simatic_s7-1500_cpu_1518f-4_pn\\/dp_mfp_firmware:*:*:*:*:*:*:*:*')!;
    expect(cpe.part).toBe('o');
    expect(cpe.product).toBe('simatic_s7-1500_cpu_1518f-4_pn\\/dp_mfp_firmware');
    expect(parseCpe('cpe:2.3:a:joomla:joomla\\!:4.0.0:*:*:*:*:*:*:*')!.product).toBe('joomla\\!');
    expect(parseCpe('not-a-cpe')).toBeNull();
  });

  it('builds NVD match strings and query URLs', () => {
    expect(buildMatchString('jquery:jquery', '3.4.1')).toBe('cpe:2.3:a:jquery:jquery:3.4.1');
    const url = new URL(nvdQueryUrl('f5:nginx', '1.18.0'));
    expect(url.searchParams.get('virtualMatchString')).toBe('cpe:2.3:a:f5:nginx:1.18.0');
    expect(url.search).toContain('noRejected');
  });
});

describe('NVD configuration evaluation', () => {
  const nvdJquery = fixture<NvdResponse>('nvd-jquery-3.4.1.json');
  const nvdNginx = fixture<NvdResponse>('nvd-nginx-1.18.0.json');

  it('matches jQuery 3.4.1 to CVE-2020-11022/11023 with fixed version 3.5.0', () => {
    const { vulns, discarded } = normalizeNvdResponse([nvdJquery], ['jquery:jquery'], '3.4.1');
    expect(discarded).toBe(0);
    expect(vulns.map((v) => v.id).sort()).toEqual(['CVE-2020-11022', 'CVE-2020-11023']);
    for (const v of vulns) {
      expect(v.fixedIn).toBe('3.5.0');
      expect(v.source).toBe('nvd');
      expect(v.sourceUrl).toBe(`https://nvd.nist.gov/vuln/detail/${v.id}`);
      expect(v.cvss).toMatchObject({ version: '3.1', score: 6.1, severity: 'MEDIUM' });
      expect(v.matchBasis).toContain('3.4.1');
    }
  });

  it('discards results the local range check does not confirm (patched version)', () => {
    const { vulns, discarded } = normalizeNvdResponse([nvdJquery], ['jquery:jquery'], '3.5.0');
    expect(vulns).toEqual([]);
    expect(discarded).toBe(2);
  });

  it('never matches by product name alone', () => {
    const { vulns } = normalizeNvdResponse([nvdJquery], ['other:product'], '3.4.1');
    expect(vulns).toEqual([]);
  });

  it('matches nginx 1.18.0 only through open-source ranges (NGINX Plus "rNN" bounds are incomparable)', () => {
    const { vulns } = normalizeNvdResponse([nvdNginx], ['f5:nginx', 'nginx:nginx'], '1.18.0');
    const ids = vulns.map((v) => v.id);
    expect(ids).toEqual(expect.arrayContaining(['CVE-2021-23017', 'CVE-2021-3618', 'CVE-2022-41741', 'CVE-2025-23419']));
    const v23017 = vulns.find((v) => v.id === 'CVE-2021-23017')!;
    expect(v23017.fixedIn).toBe('1.20.1');
    expect(v23017.affected).toEqual(['>= 0.6.18, < 1.20.1']);
    // versionEndIncluding gives no fixed release: none is invented.
    expect(vulns.find((v) => v.id === 'CVE-2022-41741')!.fixedIn).toBeUndefined();
  });

  it('reports AND configurations as conditions', () => {
    const config = [
      {
        operator: 'AND' as const,
        nodes: [
          { operator: 'OR' as const, cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', versionEndExcluding: '2.0' }] },
          { operator: 'OR' as const, cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*' }] },
        ],
      },
    ];
    const m = evaluateNvdConfigurations(config, ['acme:widget'], '1.5');
    expect(m.matched).toBe(true);
    expect(m.conditions).toContain('microsoft windows');
  });

  it('matches exact-version criteria and ignores pre-release update fields', () => {
    const config = [
      {
        nodes: [
          {
            cpeMatch: [
              { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*' },
              { vulnerable: true, criteria: 'cpe:2.3:a:acme:widget:1.2.4:beta1:*:*:*:*:*:*' },
              { vulnerable: false, criteria: 'cpe:2.3:a:acme:widget:1.2.5:*:*:*:*:*:*:*' },
            ],
          },
        ],
      },
    ];
    expect(evaluateNvdConfigurations(config, ['acme:widget'], '1.2.3').matched).toBe(true);
    expect(evaluateNvdConfigurations(config, ['acme:widget'], '1.2.4').matched).toBe(false);
    expect(evaluateNvdConfigurations(config, ['acme:widget'], '1.2.5').matched).toBe(false);
  });

  it('derives titles from the description, skipping product introductions', () => {
    expect(titleFromDescription('WordPress is an open publishing platform for the Web. Unsanitized input allows stored XSS. More.')).toBe(
      'Unsanitized input allows stored XSS.',
    );
    expect(titleFromDescription('jQuery before 3.5.0 allows XSS via htmlPrefilter. Details follow.')).toBe('jQuery before 3.5.0 allows XSS via htmlPrefilter.');
    expect(titleFromDescription('Short')).toBe('Short');
  });

  it('prefers the NVD Primary CVSS assessment', () => {
    const cve = nvdJquery.vulnerabilities![0]!.cve;
    expect(pickCvss(cve.metrics)?.source).toBe('nvd@nist.gov');
  });
});

describe('OSV evaluation', () => {
  const osvJquery = fixture<OsvResponse>('osv-jquery-3.4.1.json');
  const osvLodash = fixture<OsvResponse>('osv-lodash-4.17.15.json');

  it('normalizes GHSA advisories to CVE ids with GitHub/OSV links', () => {
    const { vulns, discarded } = normalizeOsvResponse([osvJquery], 'npm', 'jquery', '3.4.1');
    expect(discarded).toBe(0);
    expect(vulns.map((v) => v.id).sort()).toEqual(['CVE-2020-11022', 'CVE-2020-11023']);
    const v = vulns.find((x) => x.id === 'CVE-2020-11022')!;
    expect(v.aliases).toContain('GHSA-gxr4-xjj5-5px2');
    expect(v.fixedIn).toBe('3.5.0');
    expect(v.cvss).toMatchObject({ score: 6.9, severity: 'MEDIUM' });
    expect(v.references[0]).toEqual({ url: 'https://github.com/advisories/GHSA-gxr4-xjj5-5px2', label: 'GitHub Advisory' });
    expect(v.sourceUrl).toBe('https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2');
  });

  it('only evaluates ranges of the exact package (ignores other ecosystems in the advisory)', () => {
    const vuln = osvJquery.vulns!.find((v) => v.id === 'GHSA-gxr4-xjj5-5px2')!;
    // 4.0.0 is outside the npm range (fixed 3.5.0) but inside another package's range (fixed 4.4.0).
    expect(evaluateOsvAffected(vuln.affected as never, 'npm', 'jquery', '4.0.0').matched).toBe(false);
    expect(evaluateOsvAffected(vuln.affected as never, 'npm', 'jquery', '1.11.0').matched).toBe(false);
    expect(evaluateOsvAffected(vuln.affected as never, 'npm', 'jquery', '1.12.0').matched).toBe(true);
  });

  it('computes fixed versions per advisory for lodash 4.17.15', () => {
    const { vulns } = normalizeOsvResponse([osvLodash], 'npm', 'lodash', '4.17.15');
    const byId = Object.fromEntries(vulns.map((v) => [v.id, v]));
    expect(byId['CVE-2020-8203']?.fixedIn).toBe('4.17.19');
    expect(byId['CVE-2021-23337']?.fixedIn).toBe('4.17.21');
    expect(byId['CVE-2021-23337']?.cvss?.score).toBe(7.2);
  });

  it('drops advisories whose ranges do not contain the version', () => {
    const { vulns, discarded } = normalizeOsvResponse([osvLodash], 'npm', 'lodash', '4.18.0');
    expect(vulns).toEqual([]);
    expect(discarded).toBe(osvLodash.vulns!.length);
  });

  it('supports last_affected and explicit version lists', () => {
    const affected = [
      { package: { ecosystem: 'npm', name: 'x' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { last_affected: '1.4.2' }] }] },
      { package: { ecosystem: 'npm', name: 'x' }, versions: ['2.0.0'] },
    ];
    expect(evaluateOsvAffected(affected, 'npm', 'x', '1.4.2').matched).toBe(true);
    expect(evaluateOsvAffected(affected, 'npm', 'x', '1.4.3').matched).toBe(false);
    expect(evaluateOsvAffected(affected, 'npm', 'x', '2.0.0').matched).toBe(true);
  });
});

describe('CVSS v3 calculator', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N', 6.9],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N/E:H', 6.9],
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2],
    ['CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N', 0],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
  ])('%s → %d', (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score);
  });

  it('rejects malformed vectors', () => {
    expect(cvss3BaseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
    expect(cvss3BaseScore('CVSS:2.0/AV:N')).toBeNull();
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
  });

  it('rounds up per specification and maps severities', () => {
    expect(roundUp(4.02)).toBe(4.1);
    expect(roundUp(4.0)).toBe(4);
    expect(severityFromScore(9.8)).toBe('CRITICAL');
    expect(severityFromScore(0)).toBe('NONE');
    expect(severityFromScore(null)).toBe('UNKNOWN');
  });
});
