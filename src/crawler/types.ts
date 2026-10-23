import type { Detection, PageSnapshot } from '../types';

/** Result of fetching and parsing one page. Produced by the offscreen fetcher. */
export interface FetchedPage {
  requestedUrl: string;
  finalUrl: string;
  ok: boolean;
  status: number;
  contentType: string;
  /** Lower-cased response headers (sensitive values redacted before this point). */
  headers: Record<string, string>;
  /** Raw anchor hrefs found in the document (resolved against the page). */
  links: string[];
  /** Engine input built from the parsed document + response headers. */
  snapshot: PageSnapshot;
  /** External scripts without an integrity attribute (for the SRI check). */
  scriptsWithoutIntegrity?: string[];
  bytes: number;
  error?: string;
  skippedReason?: 'not-html' | 'too-large' | 'error';
}

/** A fetcher abstracts how a page is retrieved and parsed (real = offscreen; tests = fake). */
export type PageFetcher = (url: string) => Promise<FetchedPage>;

/** Persisted per-page record. */
export interface PageRecord {
  key: string;
  sessionId: string;
  url: string;
  finalUrl: string;
  depth: number;
  status: number;
  contentType: string;
  technologies: string[];
  outlinks: number;
  fetchedAt: string;
  error?: string;
}

/** An observed host and what kinds of resources it served. */
export interface AssetRecord {
  key: string;
  sessionId: string;
  host: string;
  count: number;
  thirdParty: boolean;
}

export interface CrawlProgress {
  fetched: number;
  queued: number;
  skipped: number;
  errors: number;
  currentDepth: number;
  lastUrl?: string;
}

export interface CrawlCallbacks {
  onPage: (page: FetchedPage, depth: number, detections: Detection[]) => void | Promise<void>;
  onProgress?: (progress: CrawlProgress) => void;
  /** Return false to stop the crawl (pause/abort). Checked before each fetch. */
  shouldContinue?: () => boolean;
}

export interface CrawlSummary {
  fetched: number;
  skipped: number;
  errors: number;
  reachedLimit: boolean;
  aborted: boolean;
}
