// Injected on demand (chrome.scripting.executeScript, files: ['content.js']) into the top frame,
// in the extension's isolated world. It only reads what the page already exposes to scripts:
// markup, script/style URLs, meta tags, cookie *names*, Performance API resource URLs and
// the DOM queries requested by the signatures. Nothing is sent anywhere; the result is returned
// to the service worker for local analysis. Cookie values are never read beyond their length.

import type { CollectedDom, DomQuery, DomQueryResult, ResourceEntry, ScriptInfo } from '../types';

const LIMITS = {
  html: 1_000_000,
  inlineScriptEach: 20_000,
  inlineScriptTotal: 300_000,
  scripts: 300,
  stylesheets: 200,
  resources: 600,
  metaValue: 1000,
  domValues: 5,
  domValue: 200,
};

function cut(s: string | null | undefined, max: number): string {
  if (!s) return '';
  return s.length > max ? s.slice(0, max) : s;
}

function collectScripts(): { scripts: ScriptInfo[]; inline: string; inlineCount: number } {
  const scripts: ScriptInfo[] = [];
  let inline = '';
  let inlineCount = 0;
  for (const el of Array.from(document.scripts)) {
    if (el.src) {
      if (scripts.length < LIMITS.scripts) {
        scripts.push({
          src: el.src,
          integrity: el.hasAttribute('integrity') && el.integrity.length > 0,
          crossorigin: el.getAttribute('crossorigin'),
          async: el.async,
          defer: el.defer,
          module: el.type === 'module',
        });
      }
    } else {
      inlineCount++;
      if (inline.length < LIMITS.inlineScriptTotal) inline += `${cut(el.textContent, LIMITS.inlineScriptEach)}\n`;
    }
  }
  return { scripts, inline: cut(inline, LIMITS.inlineScriptTotal), inlineCount };
}

function collectStylesheets(): string[] {
  const out: string[] = [];
  for (const el of Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel~="stylesheet"][href], link[rel="preload"][as="style"][href]'))) {
    if (out.length >= LIMITS.stylesheets) break;
    out.push(el.href);
  }
  return out;
}

function collectMeta(): Record<string, string[]> {
  const meta: Record<string, string[]> = {};
  for (const el of Array.from(document.querySelectorAll('meta'))) {
    const key = (el.getAttribute('name') ?? el.getAttribute('property') ?? el.getAttribute('http-equiv') ?? '').trim().toLowerCase();
    const content = el.getAttribute('content');
    if (!key || content === null) continue;
    (meta[key] ??= []).push(cut(content, LIMITS.metaValue));
  }
  return meta;
}

function collectCookies(): { names: string[]; lengths: Record<string, number> } {
  const names: string[] = [];
  const lengths: Record<string, number> = {};
  let raw = '';
  try {
    raw = document.cookie;
  } catch {
    // Sandboxed documents throw on cookie access.
  }
  for (const pair of raw.split(';')) {
    const idx = pair.indexOf('=');
    const name = (idx >= 0 ? pair.slice(0, idx) : pair).trim();
    if (!name || name.length > 128 || name in lengths) continue;
    names.push(name);
    lengths[name] = idx >= 0 ? pair.length - idx - 1 : 0;
  }
  return { names, lengths };
}

function collectResources(): ResourceEntry[] {
  try {
    return (performance.getEntriesByType('resource') as PerformanceResourceTiming[])
      .slice(0, LIMITS.resources)
      .map((e) => ({ url: e.name, initiatorType: e.initiatorType }));
  } catch {
    return [];
  }
}

function runDomQueries(queries: DomQuery[]): Record<string, DomQueryResult> {
  const out: Record<string, DomQueryResult> = {};
  for (const q of queries) {
    let nodes: Element[];
    try {
      nodes = Array.from(document.querySelectorAll(q.selector));
    } catch {
      continue;
    }
    if (!nodes.length) continue;
    const values: string[] = [];
    for (const node of nodes.slice(0, LIMITS.domValues)) {
      if (q.attribute) {
        const v = node.getAttribute(q.attribute);
        if (v !== null) values.push(cut(v, LIMITS.domValue));
      } else if (q.text) {
        values.push(cut(node.textContent?.trim(), LIMITS.domValue));
      }
    }
    out[q.id] = { count: nodes.length, values };
  }
  return out;
}

function collect(domQueries: DomQuery[]): CollectedDom {
  const html = document.documentElement?.outerHTML ?? '';
  const { scripts, inline, inlineCount } = collectScripts();
  const cookies = collectCookies();
  return {
    url: location.href,
    title: cut(document.title, 300),
    html: cut(html, LIMITS.html),
    htmlTruncated: html.length > LIMITS.html,
    scripts,
    inlineScripts: inline,
    inlineScriptCount: inlineCount,
    stylesheets: collectStylesheets(),
    meta: collectMeta(),
    cookieNames: cookies.names,
    cookieValueLengths: cookies.lengths,
    resources: collectResources(),
    dom: runDomQueries(Array.isArray(domQueries) ? domQueries : []),
    protocol: location.protocol,
    contentType: document.contentType,
    characterSet: document.characterSet,
  };
}

(globalThis as unknown as { __techreconCollect: typeof collect }).__techreconCollect = collect;
