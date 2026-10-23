// Drives a scan session: crawls the scope, aggregates technologies site-wide, persists pages,
// assets and the inventory to IndexedDB, and reports progress. Once the crawl ends, the
// inventory is correlated with vulnerability sources (cvePhase.ts). Misconfig checks come later.

import { TechAggregator } from '../crawler/aggregate';
import { crawl, type CrawlDeps } from '../crawler/crawler';
import type { AssetRecord, FetchedPage, PageRecord } from '../crawler/types';
import { put } from '../db';
import { siteOf } from '../recon';
import { HostRateLimiter } from '../scope/limits';
import type { Detection } from '../types';
import { runCvePhase, type CveDeps } from './cvePhase';
import { assertRunnable, saveSession } from './session';
import { emptyCounters, type ScanSession } from './types';

export interface ScanRunHandle {
  session: ScanSession;
  promise: Promise<ScanSession>;
  abort: () => void;
}

export interface ScanRunnerDeps {
  fetcher: CrawlDeps['fetcher'];
  signatures?: CrawlDeps['signatures'];
  onUpdate: (session: ScanSession) => void;
  /** Vulnerability correlation after the crawl; absent when CVE lookup is disabled. */
  cve?: CveDeps;
  now?: () => number;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/** Starts a crawl for an authorized session. Returns a handle with an abort hook. */
export function runScan(session: ScanSession, deps: ScanRunnerDeps): ScanRunHandle {
  assertRunnable(session);
  let aborted = false;
  const abort = () => {
    aborted = true;
  };

  const promise = (async (): Promise<ScanSession> => {
    const seedSite = session.scope.seeds[0] ? siteOf(hostOf(session.scope.seeds[0])) : '';
    const aggregator = new TechAggregator();
    const assetCounts = new Map<string, { count: number; host: string }>();
    let pageIndex = 0;

    session.status = 'running';
    session.startedAt = new Date().toISOString();
    session.counters = emptyCounters();
    await saveSession(session);
    deps.onUpdate(session);

    const recordAsset = (url: string) => {
      const host = hostOf(url);
      if (!host) return;
      const entry = assetCounts.get(host) ?? { count: 0, host };
      entry.count++;
      assetCounts.set(host, entry);
    };

    const onPage = async (page: FetchedPage, depth: number, detections: Detection[]) => {
      pageIndex++;
      aggregator.add(detections, page.finalUrl);
      recordAsset(page.finalUrl);
      for (const src of page.snapshot.scriptSrcs) recordAsset(src);

      const record: PageRecord = {
        key: `${session.id}:${pageIndex}`,
        sessionId: session.id,
        url: page.requestedUrl,
        finalUrl: page.finalUrl,
        depth,
        status: page.status,
        contentType: page.contentType,
        technologies: detections.filter((d) => !d.inferred).map((d) => d.id),
        outlinks: page.links.length,
        fetchedAt: new Date().toISOString(),
        error: page.error,
      };
      await put('pages', record).catch(() => undefined);

      session.counters.fetched = pageIndex;
      session.counters.technologies = aggregator.size;
      if (page.error) session.counters.errors++;
      if (page.skippedReason) session.counters.skipped++;
      deps.onUpdate(session);
    };

    try {
      const rateLimiter = new HostRateLimiter(session.scope.requestsPerSecond);
      const summary = await crawl(
        session.scope,
        { fetcher: deps.fetcher, rateLimiter, signatures: deps.signatures },
        { onPage, shouldContinue: () => !aborted },
      );

      // Persist the aggregated inventory and the asset map.
      const inventory = aggregator.finish();
      for (const tech of inventory) {
        await put('techFindings', { key: `${session.id}:${tech.id}`, sessionId: session.id, ...tech }).catch(() => undefined);
      }
      for (const { host, count } of assetCounts.values()) {
        const asset: AssetRecord = { key: `${session.id}:${host}`, sessionId: session.id, host, count, thirdParty: seedSite !== '' && siteOf(host) !== seedSite };
        await put('assets', asset).catch(() => undefined);
      }

      session.counters.technologies = inventory.length;

      if (summary.aborted) {
        // Nothing more to do: the operator stopped the scan.
      } else if (deps.cve) {
        await runCvePhase(session, inventory, deps.cve, {
          shouldContinue: () => !aborted,
          onUpdate: () => {
            void saveSession(session).catch(() => undefined);
            deps.onUpdate(session);
          },
        });
      } else {
        session.cve = { status: 'disabled', total: inventory.length, eligible: 0, done: 0, errors: 0 };
      }
      session.status = summary.aborted || session.cve?.status === 'aborted' ? 'aborted' : 'done';
      session.finishedAt = new Date().toISOString();
    } catch (err) {
      session.status = 'error';
      session.error = err instanceof Error ? err.message : String(err);
      session.finishedAt = new Date().toISOString();
    }

    await saveSession(session);
    deps.onUpdate(session);
    return session;
  })();

  return { session, promise, abort };
}
