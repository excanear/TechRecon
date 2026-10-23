import { redactHeaders, redactUrl } from '../shared/redact';
import { sanitizeText } from '../shared/sanitize';
import type {
  CollectedDom,
  CookieObservation,
  HeaderProbe,
  HostInventory,
  ReconData,
  ScriptInventoryItem,
  SecurityHeaderCheck,
} from '../types';

// Multi-label public suffixes common enough to matter for first/third-party grouping.
// This is a heuristic (no full Public Suffix List is bundled) and is labelled as such in the UI.
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.br', 'net.br', 'org.br', 'gov.br', 'com.au', 'net.au', 'org.au',
  'co.jp', 'ne.jp', 'or.jp', 'co.nz', 'co.za', 'com.mx', 'com.ar', 'com.cn', 'com.tr', 'co.in', 'co.kr', 'com.sg',
  'com.hk', 'com.tw', 'co.il', 'com.pl', 'com.co', 'com.pe', 'com.pt',
]);

export function siteOf(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return MULTI_LABEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

function hostOf(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.hostname : null;
  } catch {
    return null;
  }
}

export function cspNotes(csp: string): string[] {
  const notes: string[] = [];
  const directives = new Map<string, string>();
  for (const part of csp.split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) directives.set(name.toLowerCase(), values.join(' '));
  }
  const scriptSrc = directives.get('script-src') ?? directives.get('default-src');
  if (scriptSrc === undefined) notes.push('Sem script-src/default-src: scripts não são restringidos.');
  else {
    if (scriptSrc.includes("'unsafe-inline'") && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc)) {
      notes.push("script-src permite 'unsafe-inline' sem nonce/hash.");
    }
    if (scriptSrc.includes("'unsafe-eval'")) notes.push("script-src permite 'unsafe-eval'.");
    if (/(^|\s)(\*|https?:|data:)(\s|$)/.test(scriptSrc)) notes.push('script-src contém fonte curinga (*, https: ou data:).');
  }
  if (!directives.has('object-src') && !(directives.get('default-src') ?? '').includes("'none'")) {
    notes.push("object-src não definido como 'none'.");
  }
  if (!directives.has('frame-ancestors')) notes.push('frame-ancestors não definido.');
  return notes;
}

export function hstsNotes(value: string): string[] {
  const notes: string[] = [];
  const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(value)?.[1] ?? NaN);
  if (!Number.isFinite(maxAge)) notes.push('max-age ausente ou inválido.');
  else if (maxAge < 15552000) notes.push(`max-age baixo (${maxAge} s; recomendado ≥ 180 dias).`);
  if (!/includesubdomains/i.test(value)) notes.push('Sem includeSubDomains.');
  if (/preload/i.test(value)) notes.push('Marcado para preload.');
  return notes;
}

function check(
  id: string,
  label: string,
  headers: Record<string, string> | null,
  meta?: string,
  analyse?: (value: string) => string[],
): SecurityHeaderCheck {
  const headerValue = headers?.[id];
  if (headerValue !== undefined) {
    return { id, label, state: 'present', value: sanitizeText(headerValue, 600), origin: 'header', notes: analyse?.(headerValue) ?? [] };
  }
  if (meta !== undefined) {
    return { id, label, state: 'present', value: sanitizeText(meta, 600), origin: 'meta', notes: analyse?.(meta) ?? [] };
  }
  // Without a header probe, absence cannot be observed.
  return { id, label, state: headers ? 'absent' : 'not-observed', notes: [] };
}

export function buildRecon(dom: CollectedDom, probe: HeaderProbe | null): ReconData {
  const https = dom.protocol === 'https:';
  const headers = probe?.headers ?? null;
  const pageHost = hostOf(dom.url) ?? '';
  const pageSite = siteOf(pageHost);
  const notes: string[] = [];

  const cspMeta = dom.meta['content-security-policy']?.[0];
  const referrerMeta = dom.meta['referrer']?.[0];

  const securityHeaders: SecurityHeaderCheck[] = [
    check('content-security-policy', 'Content-Security-Policy', headers, cspMeta, cspNotes),
    check('content-security-policy-report-only', 'CSP (Report-Only)', headers),
    https
      ? check('strict-transport-security', 'Strict-Transport-Security', headers, undefined, hstsNotes)
      : { id: 'strict-transport-security', label: 'Strict-Transport-Security', state: 'not-observed', notes: ['Página servida sem HTTPS: HSTS não se aplica.'] },
    check('x-frame-options', 'X-Frame-Options', headers),
    check('x-content-type-options', 'X-Content-Type-Options', headers, undefined, (v) => (/^\s*nosniff\s*$/i.test(v) ? [] : ['Valor diferente de "nosniff".'])),
    check('referrer-policy', 'Referrer-Policy', headers, referrerMeta, (v) => (/unsafe-url/i.test(v) ? ['unsafe-url envia a URL completa a terceiros.'] : [])),
    check('permissions-policy', 'Permissions-Policy', headers),
    check('cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', headers),
    check('cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy', headers),
    check('cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', headers),
  ];

  const xfo = securityHeaders.find((h) => h.id === 'x-frame-options');
  const cspCheck = securityHeaders[0]!;
  if (xfo?.state === 'absent' && cspCheck.origin === 'header' && /frame-ancestors/i.test(cspCheck.value ?? '')) {
    xfo.notes.push('Coberto por CSP frame-ancestors.');
  }
  if (cspCheck.origin === 'meta') cspCheck.notes.push('Definida via <meta>: frame-ancestors, report-uri e sandbox são ignorados neste modo.');

  if (headers) {
    for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
      const v = headers[name];
      if (v && /\d/.test(v)) notes.push(`Header ${name} divulga versão: "${sanitizeText(v, 80)}".`);
    }
  } else {
    notes.push('Headers de resposta não observados (análise passiva). Use "Capturar headers" para uma única requisição same-origin.');
  }

  const scripts: ScriptInventoryItem[] = dom.scripts.map((s) => {
    const host = hostOf(s.src) ?? '';
    return {
      url: redactUrl(s.src),
      host,
      thirdParty: host !== '' && siteOf(host) !== pageSite,
      integrity: s.integrity,
      crossorigin: s.crossorigin,
      loading: s.module ? 'module' : s.async ? 'async' : s.defer ? 'defer' : 'blocking',
      insecure: https && s.src.startsWith('http:'),
    };
  });

  const hostMap = new Map<string, HostInventory>();
  const addHost = (url: string, type: string) => {
    const host = hostOf(url);
    if (!host) return;
    const entry = hostMap.get(host) ?? { host, thirdParty: siteOf(host) !== pageSite, count: 0, types: {} };
    entry.count++;
    entry.types[type] = (entry.types[type] ?? 0) + 1;
    hostMap.set(host, entry);
  };
  const seen = new Set<string>();
  for (const r of dom.resources) {
    seen.add(r.url);
    addHost(r.url, r.initiatorType || 'other');
  }
  for (const s of dom.scripts) if (!seen.has(s.src)) addHost(s.src, 'script');
  for (const href of dom.stylesheets) if (!seen.has(href)) addHost(href, 'link');
  const hosts = [...hostMap.values()].sort((a, b) => Number(a.thirdParty) - Number(b.thirdParty) || b.count - a.count);

  const mixedContent = https
    ? [...new Set([...dom.resources.map((r) => r.url), ...dom.scripts.map((s) => s.src), ...dom.stylesheets].filter((u) => u.startsWith('http:')))]
        .slice(0, 50)
        .map(redactUrl)
    : [];

  const cookies: CookieObservation[] = dom.cookieNames.map((name) => ({
    name: sanitizeText(name, 128),
    valueLength: dom.cookieValueLengths[name] ?? 0,
  }));

  const thirdPartyWithoutSri = scripts.filter((s) => s.thirdParty && !s.integrity).length;
  if (thirdPartyWithoutSri) notes.push(`${thirdPartyWithoutSri} script(s) de terceiros sem Subresource Integrity.`);
  if (mixedContent.length) notes.push(`${mixedContent.length} recurso(s) carregado(s) via HTTP em página HTTPS.`);

  return {
    https,
    headerSource: probe ? 'probe' : 'none',
    headerStatus: probe?.status,
    headers: headers ? redactHeaders(headers) : {},
    securityHeaders,
    scripts,
    inlineScriptCount: dom.inlineScriptCount,
    hosts,
    cookies,
    mixedContent,
    notes,
  };
}
