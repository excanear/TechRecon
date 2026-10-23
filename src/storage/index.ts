// Local persistence. Nothing here leaves the browser.
//  - chrome.storage.local:   settings, CVE query cache, analyst confirmations
//  - chrome.storage.session: last analysis per tab (cleared when the browser closes)

import type { CachedQuery, QueryCache } from '../cve/correlate';
import type { AnalysisState, Confirmations, Settings } from '../types';

export const DEFAULT_SETTINGS: Settings = {
  nvdApiKey: '',
  autoHeaderProbe: false,
  cveLookup: true,
  cacheTtlHours: 24,
  theme: 'dark',
};

const SETTINGS_KEY = 'settings';
const CACHE_PREFIX = 'cve:';
const MAX_CACHE_ENTRIES = 400;

export async function getSettings(): Promise<Settings> {
  const stored = (await chrome.storage.local.get(SETTINGS_KEY))[SETTINGS_KEY] as Partial<Settings> | undefined;
  return sanitizeSettings({ ...DEFAULT_SETTINGS, ...(stored ?? {}) });
}

export function sanitizeSettings(s: Partial<Settings>): Settings {
  const ttl = Number(s.cacheTtlHours);
  return {
    nvdApiKey: typeof s.nvdApiKey === 'string' ? s.nvdApiKey.trim().replace(/[^A-Za-z0-9-]/g, '').slice(0, 64) : '',
    autoHeaderProbe: Boolean(s.autoHeaderProbe),
    cveLookup: s.cveLookup !== false,
    cacheTtlHours: Number.isFinite(ttl) ? Math.min(168, Math.max(1, Math.round(ttl))) : DEFAULT_SETTINGS.cacheTtlHours,
    theme: s.theme === 'light' ? 'light' : 'dark',
  };
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = sanitizeSettings({ ...(await getSettings()), ...patch });
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

// ───────── CVE query cache ─────────

export class ChromeQueryCache implements QueryCache {
  async get(key: string): Promise<CachedQuery | undefined> {
    const k = CACHE_PREFIX + key;
    const value = (await chrome.storage.local.get(k))[k] as CachedQuery | undefined;
    if (!value || typeof value.storedAt !== 'number' || !Array.isArray(value.vulns)) return undefined;
    return value;
  }

  async set(key: string, value: CachedQuery): Promise<void> {
    await chrome.storage.local.set({ [CACHE_PREFIX + key]: value });
    await this.prune();
  }

  /** Keeps the cache bounded: drops the oldest entries above MAX_CACHE_ENTRIES. */
  async prune(maxAgeMs?: number): Promise<void> {
    const all = await chrome.storage.local.get(null);
    const entries = Object.entries(all)
      .filter(([k]) => k.startsWith(CACHE_PREFIX))
      .map(([k, v]) => [k, (v as CachedQuery)?.storedAt ?? 0] as const)
      .sort((a, b) => b[1] - a[1]);
    const now = Date.now();
    const remove = entries.filter(([, storedAt], i) => i >= MAX_CACHE_ENTRIES || (maxAgeMs !== undefined && now - storedAt > maxAgeMs)).map(([k]) => k);
    if (remove.length) await chrome.storage.local.remove(remove);
  }
}

export async function clearCveCache(): Promise<number> {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX));
  if (keys.length) await chrome.storage.local.remove(keys);
  return keys.length;
}

export async function countCveCache(): Promise<number> {
  const all = await chrome.storage.local.get(null);
  return Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX)).length;
}

// ───────── Per-tab analysis (session) ─────────

const analysisKey = (tabId: number) => `analysis:${tabId}`;

export async function loadAnalysis(tabId: number): Promise<AnalysisState | undefined> {
  const k = analysisKey(tabId);
  return (await chrome.storage.session.get(k))[k] as AnalysisState | undefined;
}

export async function saveAnalysis(state: AnalysisState): Promise<void> {
  await chrome.storage.session.set({ [analysisKey(state.tabId)]: state });
}

export async function deleteAnalysis(tabId: number): Promise<void> {
  await chrome.storage.session.remove(analysisKey(tabId));
}

// ───────── Analyst confirmations ─────────

const confirmKey = (domain: string) => `confirm:${domain}`;

export async function getConfirmations(domain: string): Promise<Confirmations> {
  const k = confirmKey(domain);
  return ((await chrome.storage.local.get(k))[k] as Confirmations | undefined) ?? {};
}

export async function setConfirmation(domain: string, vulnId: string, techId: string, confirmed: boolean): Promise<Confirmations> {
  const current = await getConfirmations(domain);
  if (confirmed) current[vulnId] = { at: new Date().toISOString(), techId };
  else delete current[vulnId];
  const k = confirmKey(domain);
  if (Object.keys(current).length) await chrome.storage.local.set({ [k]: current });
  else await chrome.storage.local.remove(k);
  return current;
}
