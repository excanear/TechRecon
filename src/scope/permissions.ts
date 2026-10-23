// Runtime host-permission handling. The extension ships with NO broad host access; it is
// requested per scan, only for the scope's hosts, and must be triggered by a user gesture
// (the "start scan" click). This keeps the broad-permission capability opt-in and scoped.

import type { ScopeConfig } from '../scan/types';

/** chrome match patterns for every host in the scope (both schemes). */
export function scopeOriginPatterns(scope: ScopeConfig): string[] {
  const patterns = new Set<string>();
  for (const matcher of scope.includeHosts) {
    const host = matcher.pattern;
    patterns.add(`https://${host}/*`);
    patterns.add(`http://${host}/*`);
    // A chrome "*.example.com" pattern matches subdomains but not the apex; add the apex too.
    if (host.startsWith('*.')) {
      const apex = host.slice(2);
      patterns.add(`https://${apex}/*`);
      patterns.add(`http://${apex}/*`);
    }
  }
  return [...patterns];
}

export function hasScopePermissions(scope: ScopeConfig): Promise<boolean> {
  const origins = scopeOriginPatterns(scope);
  if (origins.length === 0) return Promise.resolve(false);
  return chrome.permissions.contains({ origins });
}

/** Must be called from a user gesture (e.g. the scan-start click handler). */
export function requestScopePermissions(scope: ScopeConfig): Promise<boolean> {
  const origins = scopeOriginPatterns(scope);
  if (origins.length === 0) return Promise.resolve(false);
  return chrome.permissions.request({ origins });
}

/** Revokes the scope's host access (offered after a scan, to not keep broad access around). */
export function revokeScopePermissions(scope: ScopeConfig): Promise<boolean> {
  const origins = scopeOriginPatterns(scope);
  if (origins.length === 0) return Promise.resolve(true);
  return chrome.permissions.remove({ origins });
}
