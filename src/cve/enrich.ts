// Exploitation intelligence on top of version-matched vulnerabilities: CISA KEV (exploited in the
// wild) and FIRST EPSS (likelihood of exploitation), plus the priority order built from them and
// the cross-technology dedupe used by site scans.
//
// Priority, most urgent first:
//   1. listed in CISA KEV (known exploitation beats any prediction)
//   2. EPSS band: high (≥ 10%), medium (≥ 1%), then low/unscored
//   3. CVSS base score, then severity
//   4. exact EPSS score, then id (stable order)
// EPSS is banded before CVSS because small EPSS differences are noise, while a CVE that is
// genuinely likely to be exploited should not sink below a theoretical 9.8 nobody exploits.

import type { EnrichmentStatus, EpssInfo, TechVulnReport, Vulnerability } from '../types';
import { SEVERITY_RANK } from './cvss';
import { fetchEpss } from './epss';
import type { FetchLike, Sleep, Throttle } from './http';
import type { KevLoad } from './kev';

export const EPSS_HIGH = 0.1;
export const EPSS_MEDIUM = 0.01;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

export function cveIdsOf(v: Vulnerability): string[] {
  return [...new Set([v.id, ...v.aliases].filter((id) => CVE_ID.test(id)))];
}

export interface EnrichmentContext {
  fetch: FetchLike;
  /** Loads the KEV catalog (cached by the caller). */
  kev: () => Promise<KevLoad>;
  epssThrottle?: Throttle;
  sleep?: Sleep;
}

/**
 * Sets `kev` and `epss` on every vulnerability in place. A source that fails leaves its field
 * undefined (unknown) on every item and reports the error; it never turns into "not listed".
 */
export async function enrichVulns(vulns: Vulnerability[], ctx: EnrichmentContext): Promise<EnrichmentStatus> {
  const ids = [...new Set(vulns.flatMap(cveIdsOf))];
  const status: EnrichmentStatus = { kev: { ok: false, listed: 0 }, epss: { ok: false, scored: 0 }, cves: ids.length };

  const [kev, epss] = await Promise.allSettled([
    ctx.kev(),
    ids.length ? fetchEpss(ids, { fetch: ctx.fetch, throttle: ctx.epssThrottle, sleep: ctx.sleep }) : Promise.resolve(new Map<string, EpssInfo | null>()),
  ]);

  if (kev.status === 'fulfilled') {
    const { catalog, stale, refreshError } = kev.value;
    status.kev = { ok: true, catalogVersion: catalog.catalogVersion, fetchedAt: catalog.fetchedAt, stale, listed: 0 };
    if (stale) status.kev.error = `Catálogo local de ${catalog.catalogVersion} em uso; a atualização falhou: ${refreshError}`;
    for (const v of vulns) {
      v.kev = cveIdsOf(v).map((id) => catalog.entries[id]).find(Boolean) ?? null;
      if (v.kev) status.kev.listed++;
    }
  } else {
    status.kev.error = kev.reason instanceof Error ? kev.reason.message : String(kev.reason);
  }

  if (epss.status === 'fulfilled') {
    status.epss.ok = true;
    for (const v of vulns) {
      const scores = cveIdsOf(v).map((id) => epss.value.get(id)).filter((s): s is EpssInfo => Boolean(s));
      v.epss = scores.sort((a, b) => b.score - a.score)[0] ?? null;
      if (v.epss) {
        status.epss.scored++;
        status.epss.date ??= v.epss.date;
      }
    }
  } else {
    status.epss.error = epss.reason instanceof Error ? epss.reason.message : String(epss.reason);
  }
  return status;
}

/** Percent, truncated (never rounded up): 0.99999 is "99.9%", not a certainty of "100.0%". */
export function formatEpss(score: number): string {
  const digits = score < 0.01 ? 2 : 1;
  const factor = 10 ** digits;
  return `${(Math.floor(score * 100 * factor) / factor).toFixed(digits)}%`;
}

export type PriorityTier = 'kev' | 'epss-high' | 'epss-medium' | 'other';

export function priorityTier(v: Vulnerability): PriorityTier {
  if (v.kev) return 'kev';
  if (v.epss && v.epss.score >= EPSS_HIGH) return 'epss-high';
  if (v.epss && v.epss.score >= EPSS_MEDIUM) return 'epss-medium';
  return 'other';
}

const TIER_RANK: Record<PriorityTier, number> = { kev: 3, 'epss-high': 2, 'epss-medium': 1, other: 0 };

/** Sort comparator: most urgent first (see the header for the order). */
export function comparePriority(a: Vulnerability, b: Vulnerability): number {
  return (
    TIER_RANK[priorityTier(b)] - TIER_RANK[priorityTier(a)] ||
    (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) ||
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    (b.epss?.score ?? -1) - (a.epss?.score ?? -1) ||
    a.id.localeCompare(b.id)
  );
}

export interface AffectedTech {
  id: string;
  name: string;
  version?: string;
}

/** One vulnerability across the whole site, with every technology it was matched on. */
export interface VulnFinding {
  vuln: Vulnerability;
  techs: AffectedTech[];
}

/**
 * Merges the per-technology reports of a scan into unique vulnerabilities. The same CVE matched
 * through two products (e.g. two CPE aliases, or an advisory and its CVE) is listed once.
 */
export function dedupeFindings(reports: TechVulnReport[]): VulnFinding[] {
  const byId = new Map<string, VulnFinding>();
  const keyOf = new Map<string, string>();
  for (const report of reports) {
    const tech: AffectedTech = { id: report.techId, name: report.techName, version: report.version };
    for (const v of report.vulns) {
      const ids = [v.id, ...v.aliases];
      const existing = ids.map((id) => keyOf.get(id)).find(Boolean);
      if (existing) {
        const finding = byId.get(existing)!;
        const cur = finding.vuln;
        cur.aliases = [...new Set([...cur.aliases, ...ids].filter((a) => a !== cur.id))];
        cur.affected = [...new Set([...cur.affected, ...v.affected])];
        cur.fixedIn ??= v.fixedIn;
        if (!finding.techs.some((t) => t.id === tech.id)) finding.techs.push(tech);
        for (const id of ids) keyOf.set(id, existing);
        continue;
      }
      byId.set(v.id, { vuln: { ...v, aliases: [...v.aliases], affected: [...v.affected] }, techs: [tech] });
      for (const id of ids) keyOf.set(id, v.id);
    }
  }
  return [...byId.values()];
}
