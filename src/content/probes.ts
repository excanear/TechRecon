// Functions serialized by chrome.scripting.executeScript({ func }). They MUST be self-contained:
// no imports, no references to module scope – only their parameters and browser globals.

import type { DomPropertyQuery, DomQueryResult, GlobalValues } from '../types';

/**
 * Runs in the page's MAIN world to read global version markers (e.g. `jQuery.fn.jquery`) and
 * framework expandos on DOM nodes, which the isolated world cannot see. Returns only short
 * primitives or the "[object]" marker – never page objects or their contents.
 */
export function mainWorldProbe(
  paths: string[],
  domProps: DomPropertyQuery[],
): { globals: GlobalValues; dom: Record<string, DomQueryResult> } {
  const globals: GlobalValues = {};
  const describe = (value: unknown): string | undefined => {
    if (value === null || value === undefined) return undefined;
    const t = typeof value;
    if (t === 'string') return (value as string).slice(0, 100);
    if (t === 'number' || t === 'boolean' || t === 'bigint') return String(value);
    return '[object]';
  };
  for (const path of paths) {
    try {
      if (path.endsWith('*')) {
        const prefix = path.slice(0, -1);
        const key = Object.keys(window).find((k) => k.startsWith(prefix));
        if (key) globals[path] = key.slice(0, 100);
        continue;
      }
      let current: unknown = window;
      for (const part of path.split('.')) {
        if (current === null || current === undefined) break;
        if (typeof current !== 'object' && typeof current !== 'function') {
          current = undefined;
          break;
        }
        current = (current as Record<string, unknown>)[part];
      }
      const described = describe(current);
      if (described !== undefined) globals[path] = described;
    } catch {
      // Getters on page objects may throw; ignore.
    }
  }

  const dom: Record<string, DomQueryResult> = {};
  for (const q of domProps) {
    try {
      let count = 0;
      for (const el of Array.from(document.querySelectorAll(q.selector)).slice(0, 50)) {
        if (Object.keys(el).some((k) => k.startsWith(q.keyPrefix))) count++;
      }
      if (count) dom[q.id] = { count, values: [] };
    } catch {
      // Invalid selector or hostile page; ignore.
    }
  }
  return { globals, dom };
}

export interface HeaderProbeResult {
  ok: boolean;
  status?: number;
  url?: string;
  headers?: Record<string, string>;
  error?: string;
}

/**
 * Optional, user-enabled: re-requests the current URL once (same origin, like a reload) and
 * reads the response headers, aborting before the body is downloaded. Set-Cookie is never
 * exposed to scripts by the browser, so cookie attributes remain unobservable.
 */
export async function headerProbe(): Promise<HeaderProbeResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(location.href, {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'follow',
      signal: controller.signal,
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value.slice(0, 2000);
    });
    controller.abort();
    return { ok: true, status: response.status, url: response.url, headers };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? `${err.name}: ${err.message}`.slice(0, 200) : 'erro desconhecido' };
  } finally {
    clearTimeout(timer);
  }
}
