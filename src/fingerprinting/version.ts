// Version normalization and selection for detections.

const VERSION_SHAPE = /^\d+(?:\.\d+)*(?:[-.+]?[0-9A-Za-z]+)*$/;

/** Cleans a captured version string; returns null when it does not look like a version. */
export function normalizeVersion(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const v = raw.trim().replace(/^v(?=\d)/i, '').replace(/[.\-+]+$/, '');
  if (!v || v.length > 40 || !VERSION_SHAPE.test(v)) return null;
  return v;
}

/** A concrete release (at least major.minor) – a bare major such as "Drupal 10" is not enough to correlate. */
export function isExactVersion(version: string): boolean {
  return /^\d+\.\d+/.test(version);
}

export interface VersionCandidate {
  version: string;
  weight: number;
}

function isPrefixOf(short: string, long: string): boolean {
  return long !== short && (long.startsWith(`${short}.`) || long.startsWith(`${short}-`));
}

/**
 * Picks the best-supported version. Less specific versions that are a prefix of a more
 * specific one ("3" vs "3.6.0") reinforce it instead of conflicting with it.
 */
export function mergeVersionCandidates(candidates: VersionCandidate[]): { version?: string; conflicts: string[] } {
  const weights = new Map<string, number>();
  for (const c of candidates) weights.set(c.version, (weights.get(c.version) ?? 0) + c.weight);

  const versions = [...weights.keys()];
  for (const short of versions) {
    const longer = versions.filter((v) => isPrefixOf(short, v));
    if (longer.length === 0) continue;
    const share = (weights.get(short) ?? 0) / longer.length;
    for (const l of longer) weights.set(l, (weights.get(l) ?? 0) + share);
    weights.delete(short);
  }

  const ranked = [...weights.entries()].sort((a, b) => b[1] - a[1] || b[0].length - a[0].length || a[0].localeCompare(b[0]));
  if (!ranked.length) return { conflicts: [] };
  return { version: ranked[0]![0], conflicts: ranked.slice(1).map(([v]) => v) };
}
