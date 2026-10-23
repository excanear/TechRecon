// Pure HTML → engine-input extraction. Runs in the offscreen document (which has DOMParser),
// but the parsing itself is a pure function of a Document, so it is unit-testable with jsdom.

import { redactHeaders } from '../shared/redact';
import type { PageSnapshot } from '../types';

const LIMITS = { scripts: 400, stylesheets: 200, links: 2000, inlineTotal: 300_000, metaValue: 1000 };

export interface ExtractResult {
  snapshot: PageSnapshot;
  links: string[];
}

/** Builds a PageSnapshot and the raw outbound links from a parsed document + response headers. */
export function extractFromDocument(doc: Document, finalUrl: string, rawHeaders: Record<string, string>): ExtractResult {
  const abs = (value: string | null): string | null => {
    if (!value) return null;
    try {
      return new URL(value, finalUrl).toString();
    } catch {
      return null;
    }
  };

  const scriptSrcs: string[] = [];
  let inlineScripts = '';
  for (const el of Array.from(doc.querySelectorAll('script'))) {
    const src = el.getAttribute('src');
    if (src) {
      const u = abs(src);
      if (u && scriptSrcs.length < LIMITS.scripts) scriptSrcs.push(u);
    } else if (inlineScripts.length < LIMITS.inlineTotal) {
      inlineScripts += `${el.textContent ?? ''}\n`;
    }
  }

  const stylesheets: string[] = [];
  for (const el of Array.from(doc.querySelectorAll('link[rel~="stylesheet"][href], link[rel="preload"][as="style"][href]'))) {
    const u = abs(el.getAttribute('href'));
    if (u && stylesheets.length < LIMITS.stylesheets) stylesheets.push(u);
  }

  const meta: Record<string, string[]> = {};
  for (const el of Array.from(doc.querySelectorAll('meta'))) {
    const key = (el.getAttribute('name') ?? el.getAttribute('property') ?? el.getAttribute('http-equiv') ?? '').trim().toLowerCase();
    const content = el.getAttribute('content');
    if (!key || content === null) continue;
    (meta[key] ??= []).push(content.slice(0, LIMITS.metaValue));
  }

  const links: string[] = [];
  const base = doc.querySelector('base[href]')?.getAttribute('href');
  const baseUrl = base ? abs(base) ?? finalUrl : finalUrl;
  for (const el of Array.from(doc.querySelectorAll('a[href]'))) {
    if (links.length >= LIMITS.links) break;
    try {
      links.push(new URL(el.getAttribute('href')!, baseUrl).toString());
    } catch {
      // Ignore malformed hrefs.
    }
  }

  const snapshot: PageSnapshot = {
    url: finalUrl,
    html: doc.documentElement?.outerHTML?.slice(0, 1_000_000) ?? '',
    scriptSrcs,
    inlineScripts: inlineScripts.slice(0, LIMITS.inlineTotal),
    stylesheets,
    meta,
    cookieNames: [], // Not readable from a fetched response (Set-Cookie is hidden from fetch).
    headers: redactHeaders(rawHeaders),
    globals: {}, // No script execution on a fetched page.
    dom: {},
    resources: [],
  };
  return { snapshot, links };
}
