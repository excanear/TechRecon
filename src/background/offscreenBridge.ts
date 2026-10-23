// Manages the single offscreen document and the fetch request/response plumbing. The service
// worker has no DOMParser, so page parsing is delegated to the offscreen document.

import type { FetchedPage } from '../crawler/types';

const OFFSCREEN_PATH = 'offscreen.html';
let creating: Promise<void> | null = null;

async function hasOffscreen(): Promise<boolean> {
  // getContexts is the supported way to check; fall back to false if unavailable.
  const anyRuntime = chrome.runtime as unknown as {
    getContexts?: (f: { contextTypes: string[] }) => Promise<unknown[]>;
  };
  if (!anyRuntime.getContexts) return false;
  const contexts = await anyRuntime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
  return contexts.length > 0;
}

export async function ensureOffscreen(): Promise<void> {
  if (await hasOffscreen()) return;
  if (creating) return creating;
  creating = chrome.offscreen
    .createDocument({
      url: OFFSCREEN_PATH,
      reasons: ['DOM_PARSER' as chrome.offscreen.Reason],
      justification: 'Parse fetched in-scope pages to fingerprint technologies during an authorized crawl.',
    })
    .catch((err) => {
      // A concurrent create may have already made it.
      if (!/single offscreen/i.test(String(err))) throw err;
    })
    .finally(() => {
      creating = null;
    });
  return creating;
}

export async function closeOffscreen(): Promise<void> {
  if (await hasOffscreen()) await chrome.offscreen.closeDocument().catch(() => undefined);
}

let seq = 0;

/** Asks the offscreen document to fetch + parse one URL. */
export async function offscreenFetch(url: string): Promise<FetchedPage> {
  await ensureOffscreen();
  const id = `f${++seq}`;
  const response = (await chrome.runtime.sendMessage({ type: 'techrecon-offscreen-fetch', id, url })) as
    | { id: string; result: FetchedPage }
    | undefined;
  if (!response?.result) throw new Error('Offscreen: sem resposta ao buscar a página.');
  return response.result;
}
