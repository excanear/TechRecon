import { describe, expect, it } from 'vitest';
import { CATEGORY_LABELS, type Rule } from '../src/fingerprinting/signature';
import { SIGNATURES } from '../src/fingerprinting/signatures';
import { parseCpe } from '../src/cve/cpe';

function allRules(sig: (typeof SIGNATURES)[number]): Rule[] {
  const r = sig.rules;
  return [
    ...(r.html ?? []),
    ...(r.scriptSrc ?? []),
    ...(r.script ?? []),
    ...(r.stylesheet ?? []),
    ...(r.url ?? []),
    ...(r.resource ?? []),
    ...Object.values(r.meta ?? {}).flat(),
    ...Object.values(r.headers ?? {}).flat(),
    ...Object.values(r.globals ?? {}).flat(),
    ...(r.dom ?? []).map((d) => d.rule),
  ];
}

describe('signature database integrity', () => {
  it('has unique ids', () => {
    const ids = SIGNATURES.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(SIGNATURES.map((s) => [s.id, s] as const))('%s is well-formed', (_id, sig) => {
    expect(sig.name.length).toBeGreaterThan(0);
    expect(sig.categories.length).toBeGreaterThan(0);
    for (const c of sig.categories) expect(CATEGORY_LABELS[c]).toBeDefined();
    for (const id of [...(sig.implies ?? []), ...(sig.excludes ?? [])]) {
      expect(SIGNATURES.some((s) => s.id === id), `${sig.id} references unknown ${id}`).toBe(true);
    }
    for (const vp of sig.cpe ?? []) {
      expect(vp).toMatch(/^[^:]+:[^:]+$/);
      expect(parseCpe(`cpe:2.3:a:${vp}:*:*:*:*:*:*:*:*`)).not.toBeNull();
    }
    for (const rule of allRules(sig)) {
      expect(rule.pattern.global, 'stateful /g regexes are not allowed').toBe(false);
      expect(rule.confidence).toBeGreaterThanOrEqual(0);
      expect(rule.confidence).toBeLessThanOrEqual(100);
      if (rule.version) expect(rule.version).toMatch(/\$\d/);
    }
    for (const key of Object.keys(sig.rules.headers ?? {})) expect(key).toBe(key.toLowerCase());
    for (const key of Object.keys(sig.rules.meta ?? {})) expect(key).toBe(key.toLowerCase());
    if (sig.website) expect(sig.website).toMatch(/^https?:\/\//);
  });

  it('every signature can be detected by something or is an inference target', () => {
    const implied = new Set(SIGNATURES.flatMap((s) => s.implies ?? []));
    for (const sig of SIGNATURES) {
      if (allRules(sig).length === 0 && !(sig.rules.cookies?.length)) expect(implied.has(sig.id), sig.id).toBe(true);
    }
  });

  it('covers the required categories', () => {
    const categories = new Set(SIGNATURES.flatMap((s) => s.categories));
    for (const c of ['js-framework', 'js-library', 'cms', 'analytics', 'cdn', 'waf', 'web-server'] as const) {
      expect(categories.has(c)).toBe(true);
    }
    expect(SIGNATURES.length).toBeGreaterThanOrEqual(100);
  });
});
