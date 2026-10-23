// Breadth-first, in-scope, non-destructive crawler. Pure orchestration: the actual page
// retrieval is injected (`PageFetcher`), so the whole traversal — scope, dedupe, depth and
// page caps, per-host rate limiting, concurrency, link filtering — is unit-testable without
// a browser. The crawler NEVER fetches a URL that is out of scope or not a crawlable GET link.

import { detectTechnologies } from '../fingerprinting/engine';
import { HostRateLimiter } from '../scope/limits';
import { decideScope, normalizeUrl } from '../scope/scope';
import type { ScopeConfig } from '../scan/types';
import { crawlableLinks } from './links';
import type { CrawlCallbacks, CrawlSummary, FetchedPage, PageFetcher } from './types';

/** Runs tasks with at most `concurrency` in flight; stops pulling when `stop()` is true. */
async function pool<T>(items: T[], concurrency: number, stop: () => boolean, fn: (item: T) => Promise<void>): Promise<void> {
  let index = 0;
  const worker = async () => {
    while (index < items.length && !stop()) {
      const item = items[index++]!;
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length || 1)) }, worker));
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

export interface CrawlDeps {
  fetcher: PageFetcher;
  /** Injectable for tests. */
  rateLimiter?: HostRateLimiter;
}

/**
 * Crawls `scope` level by level (BFS). Level-order makes depth and termination trivial and
 * keeps the page budget exact: the counter is checked and incremented synchronously before any
 * await, so at most `maxPages` fetches happen even with concurrency.
 */
export async function crawl(scope: ScopeConfig, deps: CrawlDeps, callbacks: CrawlCallbacks): Promise<CrawlSummary> {
  const rateLimiter = deps.rateLimiter ?? new HostRateLimiter(scope.requestsPerSecond);
  const visited = new Set<string>();
  let fetched = 0;
  let skipped = 0;
  let errors = 0;
  let aborted = false;
  let reachedLimit = false;

  const keepGoing = () => {
    if (callbacks.shouldContinue && !callbacks.shouldContinue()) aborted = true;
    return !aborted && fetched < scope.maxPages;
  };

  const seedHost = scope.seeds[0] ? hostOf(scope.seeds[0]) : '';

  // Initial frontier: in-scope, deduped seeds.
  let frontier: string[] = [];
  for (const seed of scope.seeds) {
    const norm = normalizeUrl(seed);
    if (norm && decideScope(norm, scope).inScope && !visited.has(norm)) {
      visited.add(norm);
      frontier.push(norm);
    }
  }

  for (let depth = 0; depth <= scope.maxDepth; depth++) {
    if (frontier.length === 0 || !keepGoing()) break;
    const nextFrontier = new Set<string>();

    await pool(frontier, scope.concurrency, () => !keepGoing(), async (url) => {
      // Synchronous budget check + reservation: guarantees an exact maxPages ceiling.
      if (!keepGoing()) return;
      if (fetched >= scope.maxPages) {
        reachedLimit = true;
        return;
      }
      fetched++;

      await rateLimiter.acquire(hostOf(url));
      if (aborted) return;

      let page: FetchedPage;
      try {
        page = await deps.fetcher(url);
      } catch (err) {
        errors++;
        callbacks.onProgress?.({ fetched, queued: nextFrontier.size, skipped, errors, currentDepth: depth, lastUrl: url });
        void err;
        return;
      }

      if (page.error) errors++;
      if (page.skippedReason) skipped++;

      const detections = page.skippedReason ? [] : detectTechnologies(page.snapshot);
      await callbacks.onPage(page, depth, detections);
      callbacks.onProgress?.({ fetched, queued: nextFrontier.size, skipped, errors, currentDepth: depth, lastUrl: page.finalUrl });

      // Enqueue next-level links (only if deeper levels remain).
      if (depth < scope.maxDepth && !page.skippedReason) {
        for (const link of crawlableLinks(page.links, page.finalUrl)) {
          if (visited.has(link)) continue;
          const decision = decideScope(link, scope);
          if (!decision.inScope) continue;
          // When not following subdomains, stay on the seed host.
          if (!scope.followSubdomains && seedHost && hostOf(link) !== seedHost) continue;
          visited.add(link);
          nextFrontier.add(link);
        }
      }
    });

    if (fetched >= scope.maxPages) reachedLimit = true;
    frontier = [...nextFrontier];
  }

  if (frontier.length > 0 && !aborted) reachedLimit = true;
  return { fetched, skipped, errors, reachedLimit, aborted };
}
