// Link classifier: the non-destructive guard-rail. The crawler only follows links this
// module marks crawlable. It is conservative by design — when in doubt, it does NOT crawl.
// Running inside an authenticated session, a careless crawler could log the operator out or
// trigger state-changing actions, so anything that looks non-idempotent is refused.

import { normalizeUrl } from '../scope/scope';

export type LinkVerdict =
  | { crawl: true; url: string }
  | { crawl: false; url: string | null; reason: LinkReason };

export type LinkReason =
  | 'bad-url'
  | 'non-http'
  | 'destructive-path'
  | 'state-changing-query'
  | 'non-document'
  | 'auth-transition';

// Path segments that almost always change state or end the session.
const DESTRUCTIVE_SEGMENTS =
  /(?:^|[/_-])(?:logout|log-out|logoff|signout|sign-out|disconnect|delete|destroy|remove|unsubscribe|deactivate|purge|reset|revoke|wipe)(?:$|[/_-])/i;

const AUTH_TRANSITION = /(?:^|[/_-])(?:logout|signout|sign-out|log-out|logoff)(?:$|[/_.-])/i;

// Query keys that indicate an action rather than navigation.
const STATE_CHANGING_PARAMS = /^(?:action|do|op|cmd|delete|logout|_wpnonce|nonce|token|csrf|confirm|_method)$/i;

// Extensions that are assets/downloads, not crawlable HTML documents.
const NON_DOCUMENT_EXT =
  /\.(?:zip|tar|gz|tgz|rar|7z|exe|dmg|pkg|msi|deb|rpm|apk|iso|pdf|docx?|xlsx?|pptx?|csv|rtf|odt|mp[34]|m4a|wav|ogg|flac|avi|mov|mkv|webm|png|jpe?g|gif|svg|webp|avif|ico|bmp|tiff?|woff2?|ttf|otf|eot|css|js|mjs|json|xml|rss|atom|wasm|map|bin|dll|so)(?:$|[?#])/i;

export function classifyLink(rawUrl: string, baseUrl: string): LinkVerdict {
  const trimmed = (rawUrl ?? '').trim();
  if (!trimmed || /^(?:javascript:|data:|mailto:|tel:|blob:|about:|#)/i.test(trimmed)) {
    return { crawl: false, url: null, reason: 'non-http' };
  }
  const url = normalizeUrl(trimmed, baseUrl);
  if (!url) return { crawl: false, url: null, reason: 'bad-url' };

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { crawl: false, url: null, reason: 'bad-url' };
  }

  if (AUTH_TRANSITION.test(parsed.pathname)) return { crawl: false, url, reason: 'auth-transition' };
  if (DESTRUCTIVE_SEGMENTS.test(parsed.pathname)) return { crawl: false, url, reason: 'destructive-path' };
  if (NON_DOCUMENT_EXT.test(parsed.pathname)) return { crawl: false, url, reason: 'non-document' };
  for (const key of parsed.searchParams.keys()) {
    if (STATE_CHANGING_PARAMS.test(key)) return { crawl: false, url, reason: 'state-changing-query' };
  }
  return { crawl: true, url };
}

/** Extracts crawlable, normalized link targets from anchor hrefs found on a page. */
export function crawlableLinks(hrefs: string[], baseUrl: string): string[] {
  const out = new Set<string>();
  for (const href of hrefs) {
    const verdict = classifyLink(href, baseUrl);
    if (verdict.crawl) out.add(verdict.url);
  }
  return [...out];
}
