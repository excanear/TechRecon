import type { PageSnapshot } from '../src/types';

/** Builds a minimal page snapshot; tests override only what they exercise. */
export function snapshot(overrides: Partial<PageSnapshot> = {}): PageSnapshot {
  return {
    url: 'https://example.com/',
    html: '<html><head></head><body></body></html>',
    scriptSrcs: [],
    inlineScripts: '',
    stylesheets: [],
    meta: {},
    cookieNames: [],
    headers: null,
    globals: {},
    dom: {},
    resources: [],
    ...overrides,
  };
}
