import type { Severity } from '../types';

// CVSS v3.0/v3.1 base score calculator (FIRST specification, section 7).
// OSV records carry only the vector string, so the score is derived here instead of guessed.

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC = { L: 0.77, H: 0.44 } as const;
const UI = { N: 0.85, R: 0.62 } as const;
const CIA = { H: 0.56, L: 0.22, N: 0 } as const;
const PR_U = { N: 0.85, L: 0.62, H: 0.27 } as const;
const PR_C = { N: 0.85, L: 0.68, H: 0.5 } as const;

/** CVSS v3.1 "Roundup": smallest number with one decimal >= input, robust to floating point error. */
export function roundUp(value: number): number {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function parseCvssVector(vector: string): Record<string, string> | null {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(vector.trim());
  if (!m) return null;
  const metrics: Record<string, string> = {};
  for (const part of m[1]!.split('/')) {
    const [k, v] = part.split(':');
    if (!k || !v || k in metrics) return null;
    metrics[k] = v;
  }
  return metrics;
}

export function cvss3BaseScore(vector: string): number | null {
  const m = parseCvssVector(vector);
  if (!m) return null;
  const { AV: av, AC: ac, PR: pr, UI: ui, S: s, C: c, I: i, A: a } = m;
  if (!av || !ac || !pr || !ui || !s || !c || !i || !a) return null;
  if (!(av in AV) || !(ac in AC) || !(ui in UI) || !(c in CIA) || !(i in CIA) || !(a in CIA)) return null;
  if (s !== 'U' && s !== 'C') return null;
  const prTable = s === 'C' ? PR_C : PR_U;
  if (!(pr in prTable)) return null;

  const iss = 1 - (1 - CIA[c as keyof typeof CIA]) * (1 - CIA[i as keyof typeof CIA]) * (1 - CIA[a as keyof typeof CIA]);
  const impact = s === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability =
    8.22 * AV[av as keyof typeof AV] * AC[ac as keyof typeof AC] * prTable[pr as keyof typeof prTable] * UI[ui as keyof typeof UI];
  if (impact <= 0) return 0;
  return s === 'U' ? roundUp(Math.min(impact + exploitability, 10)) : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

export function severityFromScore(score: number | null | undefined): Severity {
  if (score === null || score === undefined || !Number.isFinite(score)) return 'UNKNOWN';
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

export function normalizeSeverity(raw: unknown): Severity {
  if (typeof raw !== 'string') return 'UNKNOWN';
  const s = raw.trim().toUpperCase();
  if (s === 'MODERATE') return 'MEDIUM';
  if (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM' || s === 'LOW' || s === 'NONE') return s;
  return 'UNKNOWN';
}

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  NONE: 1,
  UNKNOWN: 0,
};
