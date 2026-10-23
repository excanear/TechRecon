import type { CollectedDom, DomQueryResult, GlobalValues, HeaderProbe, PageSnapshot } from '../types';

/** Combines the isolated-world collection, MAIN-world probe and optional headers into one engine input. */
export function buildSnapshot(
  dom: CollectedDom,
  main: { globals: GlobalValues; dom: Record<string, DomQueryResult> } | null,
  probe: HeaderProbe | null,
): PageSnapshot {
  return {
    url: dom.url,
    html: dom.html,
    scriptSrcs: dom.scripts.map((s) => s.src),
    inlineScripts: dom.inlineScripts,
    stylesheets: dom.stylesheets,
    meta: dom.meta,
    cookieNames: dom.cookieNames,
    headers: probe?.headers ?? null,
    globals: main?.globals ?? {},
    dom: { ...dom.dom, ...(main?.dom ?? {}) },
    resources: dom.resources,
  };
}
