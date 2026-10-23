// Version comparison tolerant of the formats found in NVD/OSV data and in banners:
// "1.18.0", "v2.6.14", "3.0.0-rc.1", "1.1.1k" (OpenSSL-style patch letter), "4.17.21".
// Returns null when two versions are not comparable (e.g. "r22" vs "1.18.0"), so callers
// never treat an unknown ordering as a match.

type Token = { kind: 'num'; n: number } | { kind: 'pre'; rank: number; n: number } | { kind: 'post'; s: string };

const PRE_RANK: Record<string, number> = {
  dev: 0,
  snapshot: 0,
  alpha: 1,
  a: 1,
  beta: 2,
  b: 2,
  m: 3,
  milestone: 3,
  pre: 3,
  preview: 3,
  rc: 4,
  cr: 4,
};

/** Suffixes that mean "this is the release itself". */
const NEUTRAL = new Set(['final', 'ga', 'release', 'stable', 'r']);

export function tokenize(version: string): Token[] | null {
  const s = version.trim().toLowerCase().replace(/^v(?=\d)/, '').split('+')[0] ?? '';
  if (!/^\d/.test(s) || s.length > 64) return null;
  const tokens: Token[] = [];
  for (const part of s.split(/[.\-_~]/).filter(Boolean)) {
    const pieces = part.match(/\d+|[a-z]+/g);
    if (!pieces || pieces.join('') !== part) return null;
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i]!;
      if (/^\d/.test(piece)) {
        tokens.push({ kind: 'num', n: Number(piece) });
        continue;
      }
      const attachedToNumber = i > 0 && /^\d/.test(pieces[i - 1]!);
      const next = pieces[i + 1];
      // "1.1.1k": a short letter suffix glued to a number, at the end, is a post-release patch letter.
      if (attachedToNumber && next === undefined && piece.length <= 2 && !(piece.length > 1 && piece in PRE_RANK)) {
        if (!NEUTRAL.has(piece)) tokens.push({ kind: 'post', s: piece });
        continue;
      }
      if (piece in PRE_RANK) {
        let n = 0;
        if (next !== undefined && /^\d/.test(next)) {
          n = Number(next);
          i++;
        }
        tokens.push({ kind: 'pre', rank: PRE_RANK[piece]!, n });
        continue;
      }
      if (NEUTRAL.has(piece)) continue;
      tokens.push({ kind: 'post', s: piece });
    }
  }
  return tokens;
}

function compareToken(a: Token | undefined, b: Token | undefined): number {
  if (!a && !b) return 0;
  // A missing token is an implicit ".0" of a final release.
  if (!a) return -compareToken(b, undefined);
  if (!b) {
    if (a.kind === 'num') return a.n > 0 ? 1 : 0;
    if (a.kind === 'pre') return -1;
    return 1;
  }
  if (a.kind === 'num' && b.kind === 'num') return Math.sign(a.n - b.n);
  if (a.kind === 'pre' && b.kind === 'pre') return Math.sign(a.rank - b.rank) || Math.sign(a.n - b.n);
  if (a.kind === 'post' && b.kind === 'post') return a.s < b.s ? -1 : a.s > b.s ? 1 : 0;
  const order = { pre: 0, post: 1, num: 2 } as const;
  return Math.sign(order[a.kind] - order[b.kind]);
}

/** -1 / 0 / 1, or null if the versions cannot be ordered. */
export function compareVersions(a: string, b: string): number | null {
  const ta = tokenize(a);
  const tb = tokenize(b);
  if (!ta || !tb) return null;
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    const c = compareToken(ta[i], tb[i]);
    if (c !== 0) return c;
  }
  return 0;
}

export interface VersionRange {
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
}

/** true / false, or null if any bound cannot be compared with the version. */
export function isVersionInRange(version: string, range: VersionRange): boolean | null {
  const checks: Array<[string | undefined, (c: number) => boolean]> = [
    [range.startIncluding, (c) => c >= 0],
    [range.startExcluding, (c) => c > 0],
    [range.endIncluding, (c) => c <= 0],
    [range.endExcluding, (c) => c < 0],
  ];
  for (const [bound, ok] of checks) {
    if (bound === undefined) continue;
    const c = compareVersions(version, bound);
    if (c === null) return null;
    if (!ok(c)) return false;
  }
  return true;
}

export function describeRange(range: VersionRange): string {
  const parts: string[] = [];
  if (range.startIncluding) parts.push(`>= ${range.startIncluding}`);
  if (range.startExcluding) parts.push(`> ${range.startExcluding}`);
  if (range.endIncluding) parts.push(`<= ${range.endIncluding}`);
  if (range.endExcluding) parts.push(`< ${range.endExcluding}`);
  return parts.length ? parts.join(', ') : 'todas as versões';
}
