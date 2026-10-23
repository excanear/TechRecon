// Second phase of a scan: vulnerability correlation over the aggregated inventory. Each
// technology is correlated once for the whole site (not once per page), results are deduped
// across technologies, enriched with CISA KEV + EPSS and ranked. Technologies without a mapping
// or an exact observed version are recorded with the reason and never queried.

import type { AggregatedTech } from '../crawler/aggregate';
import { correlationPrecheck, type CorrelatableTech } from '../cve/correlate';
import { comparePriority, dedupeFindings } from '../cve/enrich';
import { put } from '../db';
import type { EnrichmentStatus, TechVulnReport, Vulnerability } from '../types';
import type { ScanSession, TechCveRecord, VulnFindingRecord } from './types';

export interface CveDeps {
  correlate: (tech: CorrelatableTech) => Promise<TechVulnReport>;
  enrich: (vulns: Vulnerability[]) => Promise<EnrichmentStatus>;
}

export interface CvePhaseHooks {
  shouldContinue: () => boolean;
  onUpdate: () => void;
}

/** Runs the phase, updating `session.cve` / counters as it goes. Returns the ranked findings. */
export async function runCvePhase(
  session: ScanSession,
  inventory: AggregatedTech[],
  deps: CveDeps,
  hooks: CvePhaseHooks,
): Promise<VulnFindingRecord[]> {
  const reports: TechVulnReport[] = [];
  const eligible: AggregatedTech[] = [];
  for (const tech of inventory) {
    const blocked = correlationPrecheck(tech);
    if (blocked) reports.push({ techId: tech.id, techName: tech.name, version: tech.version, ...blocked, queries: [], vulns: [] });
    else eligible.push(tech);
  }
  session.cve = { status: 'running', total: inventory.length, eligible: eligible.length, done: 0, errors: 0 };
  hooks.onUpdate();

  for (const tech of eligible) {
    if (!hooks.shouldContinue()) {
      session.cve.status = 'aborted';
      break;
    }
    let report: TechVulnReport;
    try {
      report = await deps.correlate(tech);
    } catch (err) {
      report = {
        techId: tech.id,
        techName: tech.name,
        version: tech.version,
        status: 'error',
        message: err instanceof Error ? err.message : String(err),
        queries: [],
        vulns: [],
      };
    }
    reports.push(report);
    session.cve.done++;
    if (report.status === 'error') session.cve.errors++;
    hooks.onUpdate();
  }

  const findings = dedupeFindings(reports);
  const vulns = findings.map((f) => f.vuln);
  if (vulns.length) session.cve.enrichment = await deps.enrich(vulns);
  findings.sort((a, b) => comparePriority(a.vuln, b.vuln));

  for (const report of reports) {
    const { vulns: list, ...rest } = report;
    const record: TechCveRecord = { ...rest, key: `${session.id}:${report.techId}`, sessionId: session.id, vulnIds: list.map((v) => v.id) };
    await put('techCve', record).catch(() => undefined);
  }
  const records = findings.map((f, rank): VulnFindingRecord => ({ key: `${session.id}:${f.vuln.id}`, sessionId: session.id, rank, vuln: f.vuln, techs: f.techs }));
  for (const record of records) await put('vulnFindings', record).catch(() => undefined);

  session.counters.vulnerabilities = records.length;
  session.counters.exploited = records.filter((r) => r.vuln.kev).length;
  if (session.cve.status === 'running') session.cve.status = 'done';
  hooks.onUpdate();
  return records;
}
