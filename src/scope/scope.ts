// Scope model: decides whether a URL may be visited. Pure and deterministic so it can be
// unit-tested exhaustively. The crawler never fetches a URL this module rejects.

import type { HostMatcher, ScopeConfig } from '../scan/types';

export interface ScopeDecision {
  inScope: boolean;
  reason:
    | 'ok'
    | 'bad-url'
    | 'protocol'
    | 'host-not-included'
    | 'excluded'
    | 'subdomain-blocked';
}

/** Lowercases host, drops the fragment and default ports, and keeps the query (it can select content). */
export function normalizeUrl(raw: string, base?: string): string | null {
  let url: URL;
  try {
    url = base ? new URL(raw, base) : new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  url.hash = '';
  url.hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if ((url.protocol === 'http:' && url.port === '80') || (url.protocol === 'https:' && url.port === '443')) {
    url.port = '';
  }
  url.username = '';
  url.password = '';
  return url.toString();
}

export function registrableSeedHost(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

export function hostMatches(host: string, matcher: HostMatcher): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = matcher.pattern.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const suffix = p.slice(2);
    // "*.example.com" matches the apex and any subdomain.
    return h === suffix || h.endsWith(`.${suffix}`);
  }
  return h === p;
}

/** Converts a conservative glob (only `*` is special) into an anchored, full-string regex. */
export function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

export function decideScope(rawUrl: string, scope: ScopeConfig, base?: string): ScopeDecision {
  const url = normalizeUrl(rawUrl, base);
  if (!url) return { inScope: false, reason: 'bad-url' };

  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return { inScope: false, reason: 'bad-url' };
  }

  const included = scope.includeHosts.some((m) => hostMatches(host, m));
  if (!included) return { inScope: false, reason: 'host-not-included' };

  if (!scope.followSubdomains) {
    // Only exact hosts listed in includeHosts (no wildcard expansion) are allowed.
    const exact = scope.includeHosts.some((m) => !m.pattern.startsWith('*.') && hostMatches(host, m));
    if (!exact) return { inScope: false, reason: 'subdomain-blocked' };
  }

  for (const pattern of scope.excludePatterns) {
    if (globToRegExp(pattern).test(url)) return { inScope: false, reason: 'excluded' };
  }
  return { inScope: true, reason: 'ok' };
}

export function isInScope(rawUrl: string, scope: ScopeConfig, base?: string): boolean {
  return decideScope(rawUrl, scope, base).inScope;
}

/** Builds a default scope from one or more seed URLs. */
export function scopeFromSeeds(seeds: string[], overrides: Partial<ScopeConfig> = {}): ScopeConfig {
  const normSeeds = seeds.map((s) => normalizeUrl(s)).filter((s): s is string => s !== null);
  const hosts = [...new Set(normSeeds.map((s) => new URL(s).hostname))];
  return {
    seeds: normSeeds,
    includeHosts: hosts.map((h) => ({ pattern: h })),
    excludePatterns: [
      // Never crawl package internals or VCS metadata even if linked.
      '*/node_modules/*',
      '*/.git/*',
    ],
    maxDepth: 3,
    maxPages: 200,
    requestsPerSecond: 2,
    concurrency: 3,
    followSubdomains: false,
    ...overrides,
  };
}

const LIMITS = {
  maxDepth: [0, 12] as const,
  maxPages: [1, 5000] as const,
  requestsPerSecond: [0.2, 20] as const,
  concurrency: [1, 10] as const,
};

function clamp(n: unknown, [min, max]: readonly [number, number], fallback: number): number {
  const v = typeof n === 'number' ? n : Number(n);
  return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : fallback;
}

/** Clamps operator-provided limits to safe ranges; a browser must never hammer a target. */
export function sanitizeScope(scope: ScopeConfig): ScopeConfig {
  return {
    ...scope,
    seeds: scope.seeds.map((s) => normalizeUrl(s)).filter((s): s is string => s !== null).slice(0, 50),
    includeHosts: scope.includeHosts.filter((m) => /^\*?\.?[a-z0-9.-]+$/i.test(m.pattern)).slice(0, 100),
    excludePatterns: scope.excludePatterns.filter((p) => typeof p === 'string' && p.length <= 200).slice(0, 100),
    maxDepth: clamp(scope.maxDepth, LIMITS.maxDepth, 3),
    maxPages: clamp(scope.maxPages, LIMITS.maxPages, 200),
    requestsPerSecond: clamp(scope.requestsPerSecond, LIMITS.requestsPerSecond, 2),
    concurrency: clamp(scope.concurrency, LIMITS.concurrency, 3),
    followSubdomains: Boolean(scope.followSubdomains),
  };
}
