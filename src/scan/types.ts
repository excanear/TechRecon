// Data model for a scan session: an authorized, scoped crawl of a site.
// Everything here is persisted in IndexedDB and never leaves the browser.

import type { AffectedTech } from '../cve/enrich';
import type { EnrichmentStatus, TechVulnReport, Vulnerability } from '../types';

/** Correlation outcome for one inventory technology (vulnerabilities are stored deduped, by id). */
export interface TechCveRecord extends Omit<TechVulnReport, 'vulns'> {
  key: string;
  sessionId: string;
  vulnIds: string[];
}

/** One unique vulnerability of the site, enriched, with its priority rank (0 = most urgent). */
export interface VulnFindingRecord {
  key: string;
  sessionId: string;
  rank: number;
  vuln: Vulnerability;
  techs: AffectedTech[];
}

export interface HostMatcher {
  /** Exact host ("example.com") or wildcard suffix ("*.example.com" = apex + subdomains). */
  pattern: string;
}

export interface ScopeConfig {
  /** Starting URLs the crawl expands from. */
  seeds: string[];
  /** Hosts considered in-scope. */
  includeHosts: HostMatcher[];
  /** Glob patterns (on the full URL) that are excluded even when the host is in scope. */
  excludePatterns: string[];
  /** Max link depth from a seed (seed = depth 0). */
  maxDepth: number;
  /** Hard cap on pages fetched in the whole session. */
  maxPages: number;
  /** Requests per second, per host. */
  requestsPerSecond: number;
  /** Concurrent page fetches across the session. */
  concurrency: number;
  /** Follow links to other in-scope hosts (subdomains) or stay on the seed host only. */
  followSubdomains: boolean;
}

/**
 * Explicit, recorded authorization. A scan cannot start without it. This is a local
 * acknowledgment by the operator, stored for the audit trail — not a credential.
 */
export interface Authorization {
  acknowledged: boolean;
  /** Free-text: engagement name, ticket, or the operator's own note. */
  statement: string;
  at: string;
}

export type ScanStatus = 'draft' | 'authorized' | 'running' | 'paused' | 'done' | 'aborted' | 'error';

export interface ScanCounters {
  queued: number;
  fetched: number;
  skipped: number;
  errors: number;
  technologies: number;
  vulnerabilities: number;
  /** Unique vulnerabilities listed in CISA KEV. */
  exploited?: number;
  misconfigurations: number;
}

/** Vulnerability correlation over the aggregated inventory, after the crawl. */
export interface ScanCveState {
  status: 'disabled' | 'running' | 'done' | 'aborted';
  /** Technologies in the inventory. */
  total: number;
  /** Technologies with a mapping and an exact observed version (the ones actually queried). */
  eligible: number;
  /** Eligible technologies already queried. */
  done: number;
  /** Technologies whose every source query failed. */
  errors: number;
  enrichment?: EnrichmentStatus;
}

export interface ScanSession {
  id: string;
  label: string;
  scope: ScopeConfig;
  authorization: Authorization;
  status: ScanStatus;
  counters: ScanCounters;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  cve?: ScanCveState;
}

export function emptyCounters(): ScanCounters {
  return { queued: 0, fetched: 0, skipped: 0, errors: 0, technologies: 0, vulnerabilities: 0, misconfigurations: 0 };
}
