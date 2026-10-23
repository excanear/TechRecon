// Offscreen document: the only place in the extension with both fetch and DOMParser. It fetches
// an in-scope page (using the operator's session cookies, so authenticated areas are crawlable)
// and returns an engine-ready snapshot. It performs GET only; the crawler has already filtered
// the URL for scope and idempotency. Set-Cookie and other sensitive headers are never surfaced.

import { isSensitiveHeader, redactHeaderValue } from '../shared/redact';
import type { FetchedPage } from '../crawler/types';
import { extractFromDocument } from './extract';

const MAX_BYTES = 3_000_000;
const TIMEOUT_MS = 20_000;

export interface OffscreenRequest {
  type: 'techrecon-offscreen-fetch';
  id: string;
  url: string;
}

async function fetchPage(url: string): Promise<FetchedPage> {
  const base: FetchedPage = {
    requestedUrl: url,
    finalUrl: url,
    ok: false,
    status: 0,
    contentType: '',
    headers: {},
    links: [],
    snapshot: { url, html: '', scriptSrcs: [], inlineScripts: '', stylesheets: [], meta: {}, cookieNames: [], headers: {}, globals: {}, dom: {}, resources: [] },
    bytes: 0,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, { method: 'GET', credentials: 'include', redirect: 'follow', signal: controller.signal });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      const lower = name.toLowerCase();
      if (!isSensitiveHeader(lower)) headers[lower] = redactHeaderValue(lower, value).slice(0, 2000);
    });
    const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
    const finalUrl = response.url || url;

    if (!/text\/html|application\/xhtml\+xml/.test(contentType)) {
      return { ...base, finalUrl, ok: response.ok, status: response.status, contentType, headers, skippedReason: 'not-html' };
    }

    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    let html = '';
    let bytes = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        html += decoder.decode(value, { stream: true });
        if (bytes > MAX_BYTES) {
          await reader.cancel();
          html += decoder.decode();
          break;
        }
      }
    } else {
      html = await response.text();
      bytes = html.length;
    }

    const doc = new DOMParser().parseFromString(html, 'text/html');
    const { snapshot, links } = extractFromDocument(doc, finalUrl, headers);
    return {
      requestedUrl: url,
      finalUrl,
      ok: response.ok,
      status: response.status,
      contentType,
      headers,
      links,
      snapshot,
      bytes,
      skippedReason: bytes > MAX_BYTES ? 'too-large' : undefined,
    };
  } catch (err) {
    const name = err instanceof Error ? err.name : '';
    const message = name === 'AbortError' ? 'tempo de resposta esgotado' : err instanceof Error ? err.message : 'erro desconhecido';
    return { ...base, error: message.slice(0, 200), skippedReason: 'error' };
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((message: OffscreenRequest, sender, sendResponse) => {
  if (message?.type !== 'techrecon-offscreen-fetch' || sender.id !== chrome.runtime.id) return;
  fetchPage(message.url).then((result) => sendResponse({ id: message.id, result }));
  return true; // async response
});
