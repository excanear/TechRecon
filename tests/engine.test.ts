import { describe, expect, it } from 'vitest';
import { buildCollectionPlan, detectTechnologies, domQueryId } from '../src/fingerprinting/engine';
import { snapshot } from './helpers';

const find = (list: ReturnType<typeof detectTechnologies>, id: string) => list.find((d) => d.id === id);

describe('fingerprinting engine', () => {
  it('detects nothing on an empty page', () => {
    expect(detectTechnologies(snapshot())).toEqual([]);
  });

  it('detects jQuery and its version from the global, with evidence', () => {
    const result = detectTechnologies(snapshot({ globals: { 'jQuery.fn.jquery': '3.4.1' } }));
    const jq = find(result, 'jquery');
    expect(jq).toBeDefined();
    expect(jq!.version).toBe('3.4.1');
    expect(jq!.versionExact).toBe(true);
    expect(jq!.confidenceLevel).toBe('high');
    expect(jq!.evidence).toEqual([
      expect.objectContaining({ type: 'global', key: 'jQuery.fn.jquery', version: '3.4.1', observed: true }),
    ]);
  });

  it('extracts versions from CDN script URLs', () => {
    const result = detectTechnologies(
      snapshot({
        scriptSrcs: [
          'https://code.jquery.com/jquery-3.6.0.min.js',
          'https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js',
          'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js',
        ],
      }),
    );
    expect(find(result, 'jquery')?.version).toBe('3.6.0');
    expect(find(result, 'lodash')?.version).toBe('4.17.15');
    expect(find(result, 'bootstrap')?.version).toBe('5.3.2');
    expect(find(result, 'cdnjs')).toBeDefined();
    expect(find(result, 'jsdelivr')).toBeDefined();
  });

  it('a generic file name detects without inventing a version', () => {
    const jq = find(detectTechnologies(snapshot({ scriptSrcs: ['https://example.com/js/jquery.min.js'] })), 'jquery');
    expect(jq?.version).toBeUndefined();
    expect(jq?.confidenceLevel).toBe('medium');
  });

  it('detects WordPress from the generator and marks PHP as an inference', () => {
    const result = detectTechnologies(
      snapshot({
        meta: { generator: ['WordPress 6.4.2'] },
        html: '<link rel="https://api.w.org/" href="https://example.com/wp-json/" />',
        scriptSrcs: ['https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'],
      }),
    );
    const wp = find(result, 'wordpress')!;
    expect(wp.version).toBe('6.4.2');
    expect(wp.inferred).toBe(false);
    const php = find(result, 'php')!;
    expect(php.inferred).toBe(true);
    expect(php.version).toBeUndefined();
    expect(php.evidence[0]).toMatchObject({ type: 'implied', observed: false });
    // jQuery bundled with WordPress reports its own version, not WordPress's.
    expect(find(result, 'jquery')?.version).toBe('3.7.1');
  });

  it('does not take plugin ?ver= values as the WordPress version', () => {
    const wp = find(
      detectTechnologies(snapshot({ scriptSrcs: ['https://example.com/wp-content/plugins/foo/app.js?ver=2.1.0'], html: '<div class="wp-content/"></div>' })),
      'wordpress',
    );
    expect(wp?.version).toBeUndefined();
  });

  it('header-based detections only run when headers were observed', () => {
    expect(find(detectTechnologies(snapshot()), 'nginx')).toBeUndefined();
    const result = detectTechnologies(snapshot({ headers: { server: 'nginx/1.18.0 (Ubuntu)', 'x-powered-by': 'PHP/7.4.3' } }));
    const nginx = find(result, 'nginx')!;
    expect(nginx.version).toBe('1.18.0');
    expect(nginx.distroPackage).toBe('Ubuntu');
    expect(nginx.notes.join(' ')).toMatch(/backport/);
    expect(find(result, 'php')).toMatchObject({ version: '7.4.3', inferred: false });
  });

  it('does not confuse Apache Tomcat Coyote with Apache httpd', () => {
    const result = detectTechnologies(snapshot({ headers: { server: 'Apache-Coyote/1.1' } }));
    expect(find(result, 'apache-httpd')).toBeUndefined();
    expect(find(result, 'tomcat')).toBeDefined();
  });

  it('Lodash excludes Underscore when `_.VERSION` is the only shared evidence', () => {
    const result = detectTechnologies(snapshot({ globals: { '_.VERSION': '4.17.21', '_.cloneDeepWith': '[object]' } }));
    expect(find(result, 'lodash')?.version).toBe('4.17.21');
    expect(find(result, 'underscore')).toBeUndefined();
  });

  it('keeps Underscore when there is no Lodash-only evidence', () => {
    const result = detectTechnologies(snapshot({ globals: { '_.VERSION': '1.13.6' } }));
    expect(find(result, 'underscore')?.version).toBe('1.13.6');
    expect(find(result, 'lodash')).toBeUndefined();
  });

  it('version-only rules never create a detection', () => {
    expect(find(detectTechnologies(snapshot({ globals: { '_.VERSION': '4.17.21' } })), 'lodash')).toBeUndefined();
  });

  it('reports conflicting versions and refuses to call them exact', () => {
    const jq = find(
      detectTechnologies(snapshot({ globals: { 'jQuery.fn.jquery': '3.6.0' }, scriptSrcs: ['https://code.jquery.com/jquery-1.12.4.min.js'] })),
      'jquery',
    )!;
    expect(jq.version).toBe('3.6.0');
    expect(jq.versionConflicts).toEqual(['1.12.4']);
    expect(jq.versionExact).toBe(false);
  });

  it('a bare major version is not exact', () => {
    const drupal = find(detectTechnologies(snapshot({ meta: { generator: ['Drupal 10 (https://www.drupal.org)'] } })), 'drupal')!;
    expect(drupal.version).toBe('10');
    expect(drupal.versionExact).toBe(false);
  });

  it('uses DOM attribute queries and MAIN-world expando queries', () => {
    const plan = buildCollectionPlan();
    const ngQuery = plan.dom.find((q) => q.attribute === 'ng-version')!;
    expect(ngQuery).toBeDefined();
    const reactProp = plan.domProperties.find((q) => q.keyPrefix === '__reactContainer$')!;
    const result = detectTechnologies(
      snapshot({ dom: { [ngQuery.id]: { count: 1, values: ['17.3.4'] }, [reactProp.id]: { count: 1, values: [] } } }),
    );
    expect(find(result, 'angular')?.version).toBe('17.3.4');
    const react = find(result, 'react')!;
    expect(react.evidence[0]!.value).toMatch(/__reactContainer\$/);
  });

  it('Next.js implies React and Node.js without duplicating an observed React', () => {
    const plan = buildCollectionPlan();
    const reactProp = plan.domProperties.find((q) => q.keyPrefix === '__reactContainer$')!;
    const result = detectTechnologies(
      snapshot({
        html: '<script id="__NEXT_DATA__" type="application/json">{}</script>',
        globals: { 'next.version': '14.2.3', 'React.version': '18.3.1' },
        dom: { [reactProp.id]: { count: 1, values: [] } },
      }),
    );
    expect(result.filter((d) => d.id === 'react')).toHaveLength(1);
    const react = find(result, 'react')!;
    expect(react.inferred).toBe(false);
    expect(react.version).toBe('18.3.1');
    expect(react.impliedBy).toContain('Next.js');
    expect(find(result, 'nextjs')?.version).toBe('14.2.3');
    expect(find(result, 'nodejs')?.inferred).toBe(true);
  });

  it('matches cookies by name only and supports name patterns', () => {
    const result = detectTechnologies(snapshot({ cookieNames: ['_pk_id.1.1fff', 'incap_ses_123_456', 'PHPSESSID'] }));
    expect(find(result, 'matomo')).toBeDefined();
    expect(find(result, 'imperva')).toBeDefined();
    expect(find(result, 'php')?.inferred).toBe(false);
  });

  it('redacts credentials from evidence URLs', () => {
    const result = detectTechnologies(
      snapshot({ scriptSrcs: ['https://www.googletagmanager.com/gtm.js?id=GTM-ABC&auth=supersecretvalue123'] }),
    );
    const gtm = find(result, 'google-tag-manager')!;
    expect(gtm.evidence[0]!.value).not.toContain('supersecretvalue123');
    expect(gtm.evidence[0]!.value).toContain('auth=REDACTED');
  });

  it('flags the compromised polyfill.io domain', () => {
    const poly = find(detectTechnologies(snapshot({ scriptSrcs: ['https://polyfill.io/v3/polyfill.min.js'] })), 'polyfill-io');
    expect(poly?.notes.join(' ')).toMatch(/comprometido/);
  });

  it('is deterministic', () => {
    const page = snapshot({
      globals: { 'jQuery.fn.jquery': '3.4.1', 'Vue.version': '3.4.21' },
      headers: { server: 'cloudflare', 'cf-ray': '123-GRU' },
    });
    expect(detectTechnologies(page)).toEqual(detectTechnologies(page));
  });

  it('domQueryId is stable', () => {
    expect(domQueryId('react', 1)).toBe('react#1');
  });
});
