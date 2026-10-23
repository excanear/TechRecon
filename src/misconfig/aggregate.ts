// Site-wide view of the passive checks: one finding per check (per distinct evidence for
// resource-level checks), with how many pages showed it and a few sample URLs.

import { redactUrl } from '../shared/redact';
import { SEVERITY_ORDER, type MisconfigCheckId, type MisconfigObservation, type MisconfigSeverity } from './checks';

export interface MisconfigFinding {
  check: MisconfigCheckId;
  severity: MisconfigSeverity;
  title: string;
  detail: string;
  evidence?: string;
  /** Pages (of the crawled HTML pages) where this was observed. */
  pageCount: number;
  samplePages: string[];
}

const MAX_SAMPLES = 5;
/** Checks whose evidence differs per resource or header value and should be listed separately. */
const BY_EVIDENCE = new Set<MisconfigCheckId>(['version-disclosure', 'hsts-weak', 'csp-weak']);

export class MisconfigAggregator {
  private readonly map = new Map<string, MisconfigFinding>();
  private pages = 0;

  add(observations: MisconfigObservation[], pageUrl: string): void {
    this.pages++;
    for (const o of observations) {
      const key = BY_EVIDENCE.has(o.check) ? `${o.check}|${o.evidence ?? ''}` : o.check;
      const existing = this.map.get(key);
      if (!existing) {
        this.map.set(key, { ...o, pageCount: 1, samplePages: [redactUrl(pageUrl)] });
        continue;
      }
      existing.pageCount++;
      if (existing.samplePages.length < MAX_SAMPLES) existing.samplePages.push(redactUrl(pageUrl));
    }
  }

  /** HTML pages that were checked. */
  get checkedPages(): number {
    return this.pages;
  }

  finish(): MisconfigFinding[] {
    return [...this.map.values()].sort(
      (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.pageCount - a.pageCount || a.title.localeCompare(b.title),
    );
  }
}
