import { describe, expect, it } from 'vitest';
import { compareVersions, describeRange, isVersionInRange } from '../src/cve/version';
import { isExactVersion, mergeVersionCandidates, normalizeVersion } from '../src/fingerprinting/version';

describe('compareVersions', () => {
  it.each([
    ['1.0.0', '1.0.0', 0],
    ['1.0', '1.0.0', 0],
    ['v2.6.14', '2.6.14', 0],
    ['3.4.1', '3.5.0', -1],
    ['1.10.0', '1.9.9', 1],
    ['3.0.0-rc.1', '3.0.0', -1],
    ['3.0.0-beta.2', '3.0.0-rc.1', -1],
    ['3.0.0-alpha', '3.0.0-alpha.1', -1],
    ['1.1.1k', '1.1.1', 1],
    ['1.1.1k', '1.1.1l', -1],
    ['1.1.1k', '1.1.2', -1],
    ['4.17.21', '4.17.3', 1],
    ['10.0', '8.5', 1],
  ])('%s vs %s → %d', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
    expect(compareVersions(b, a)).toBe(expected === 0 ? 0 : -expected);
  });

  it('returns null for incomparable schemes instead of guessing', () => {
    expect(compareVersions('1.18.0', 'r22')).toBeNull();
    expect(compareVersions('*', '1.0')).toBeNull();
    expect(compareVersions('', '1.0')).toBeNull();
  });
});

describe('isVersionInRange', () => {
  it('handles inclusive and exclusive bounds', () => {
    expect(isVersionInRange('3.4.1', { startIncluding: '1.2', endExcluding: '3.5.0' })).toBe(true);
    expect(isVersionInRange('3.5.0', { startIncluding: '1.2', endExcluding: '3.5.0' })).toBe(false);
    expect(isVersionInRange('1.22.0', { startIncluding: '1.1.3', endIncluding: '1.22.0' })).toBe(true);
    expect(isVersionInRange('1.1.3', { startExcluding: '1.1.3' })).toBe(false);
    expect(isVersionInRange('1.0', {})).toBe(true);
  });

  it('is null (not a match) when a bound cannot be compared', () => {
    expect(isVersionInRange('1.18.0', { startIncluding: 'r22', endIncluding: 'r27' })).toBeNull();
  });

  it('describes ranges for humans', () => {
    expect(describeRange({ startIncluding: '1.2', endExcluding: '3.5.0' })).toBe('>= 1.2, < 3.5.0');
    expect(describeRange({})).toBe('todas as versões');
  });
});

describe('version normalization and selection', () => {
  it('normalizes and rejects garbage', () => {
    expect(normalizeVersion('v3.7.1')).toBe('3.7.1');
    expect(normalizeVersion('3.7.1.')).toBe('3.7.1');
    expect(normalizeVersion('latest')).toBeNull();
    expect(normalizeVersion('1.0 <script>')).toBeNull();
    expect(normalizeVersion('')).toBeNull();
  });

  it('requires major.minor for an exact version', () => {
    expect(isExactVersion('10')).toBe(false);
    expect(isExactVersion('10.1')).toBe(true);
  });

  it('merges less specific candidates into more specific ones', () => {
    expect(mergeVersionCandidates([{ version: '3', weight: 100 }, { version: '3.6.0', weight: 100 }])).toEqual({ version: '3.6.0', conflicts: [] });
  });

  it('reports genuinely different versions as conflicts', () => {
    const r = mergeVersionCandidates([
      { version: '3.6.0', weight: 100 },
      { version: '1.12.4', weight: 50 },
    ]);
    expect(r.version).toBe('3.6.0');
    expect(r.conflicts).toEqual(['1.12.4']);
  });
});
