// Service worker: coordinates collection → fingerprinting → recon → CVE correlation for a tab,
// streams progress to the popup over a port and keeps the last result in session storage.

import { buildSnapshot } from '../fingerprinting/snapshot';
import { detectTechnologies, type CollectionPlan } from '../fingerprinting/engine';
import { getSignatureSet } from '../fingerprinting/registry';
import { correlateDetection, correlationPrecheck, createThrottles, nvdIntervalMs, type CorrelationContext } from '../cve/correlate';
import { headerProbe, mainWorldProbe, type HeaderProbeResult } from '../content/probes';
import { buildRecon } from '../recon';
import { ChromeQueryCache, deleteAnalysis, getSettings, loadAnalysis, saveAnalysis } from '../storage';
import type { AnalysisState, BackgroundMessage, CollectedDom, HeaderProbe, PopupRequest, Settings, TechVulnReport } from '../types';
import { checkUrlSupport } from './support';
import { registerDatasetChannel } from './datasetChannel';
import { registerScanChannel } from './scanChannel';

registerScanChannel();
registerDatasetChannel();

const cache = new ChromeQueryCache();
const throttles = createThrottles();
const ports = new Map<number, Set<chrome.runtime.Port>>();
const running = new Map<number, Promise<void>>();

function broadcast(state: AnalysisState): void {
  const message: BackgroundMessage = { type: 'state', state };
  for (const port of ports.get(state.tabId) ?? []) {
    try {
      port.postMessage(message);
    } catch {
      // Popup closed in the meantime.
    }
  }
}

async function publish(state: AnalysisState): Promise<void> {
  broadcast(state);
  await saveAnalysis(state).catch(() => undefined);
}

function baseState(tabId: number, url: string, settings: Settings): AnalysisState {
  let domain = '';
  try {
    domain = new URL(url).hostname;
  } catch {
    domain = url.slice(0, 80);
  }
  return {
    tabId,
    url,
    domain,
    status: 'collecting',
    startedAt: new Date().toISOString(),
    technologies: [],
    recon: null,
    vulnReports: {},
    cveLookupEnabled: settings.cveLookup,
  };
}

async function collect(tabId: number, withHeaders: boolean, plan: CollectionPlan) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
  const [domResult] = await chrome.scripting.executeScript({
    target: { tabId },
    func: (queries) => (globalThis as unknown as { __techreconCollect: (q: unknown) => unknown }).__techreconCollect(queries),
    args: [plan.dom],
  });
  const dom = domResult?.result as CollectedDom | undefined;
  if (!dom || typeof dom.html !== 'string') throw new Error('A coleta da página não retornou dados.');

  type MainResult = ReturnType<typeof mainWorldProbe>;
  let main: MainResult | null = null;
  try {
    const [mainResult] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: mainWorldProbe,
      args: [plan.globals, plan.domProperties],
    });
    main = (mainResult?.result as MainResult | undefined) ?? null;
  } catch {
    main = null;
  }

  let probe: HeaderProbe | null = null;
  let probeError: string | undefined;
  if (withHeaders) {
    const [probeResult] = await chrome.scripting.executeScript({ target: { tabId }, func: headerProbe });
    const r = probeResult?.result as HeaderProbeResult | undefined;
    if (r?.ok && r.headers && typeof r.status === 'number') {
      probe = { status: r.status, url: r.url ?? dom.url, headers: r.headers, fetchedAt: new Date().toISOString() };
    } else {
      probeError = r?.error ?? 'sem resposta';
    }
  }
  return { dom, main, probe, probeError, mainAvailable: main !== null };
}

function correlationContext(settings: Settings): CorrelationContext {
  throttles.nvd.intervalMs = nvdIntervalMs(settings.nvdApiKey);
  return {
    fetch: (input, init) => fetch(input, init),
    cache,
    nvdApiKey: settings.nvdApiKey || undefined,
    cacheTtlMs: settings.cacheTtlHours * 3600_000,
    nvdThrottle: throttles.nvd,
    osvThrottle: throttles.osv,
  };
}

async function correlate(state: AnalysisState, settings: Settings, onlyIds?: Set<string>): Promise<void> {
  if (!settings.cveLookup) {
    for (const det of state.technologies) {
      state.vulnReports[det.id] = {
        techId: det.id,
        techName: det.name,
        version: det.version,
        status: 'disabled',
        message: 'Consulta de CVEs desativada nas opções.',
        queries: [],
        vulns: [],
      };
    }
    return;
  }
  const ctx = correlationContext(settings);
  const targets = state.technologies.filter((d) => !onlyIds || onlyIds.has(d.id));
  for (const det of targets) {
    const blocked = correlationPrecheck(det);
    state.vulnReports[det.id] = blocked
      ? { techId: det.id, techName: det.name, version: det.version, ...blocked, queries: [], vulns: [] }
      : { techId: det.id, techName: det.name, version: det.version, status: 'pending', queries: [], vulns: [] };
  }
  await publish(state);

  const pending = targets.filter((d) => state.vulnReports[d.id]?.status === 'pending');
  await Promise.all(
    pending.map(async (det) => {
      let report: TechVulnReport;
      try {
        report = await correlateDetection(det, ctx);
      } catch (err) {
        report = {
          techId: det.id,
          techName: det.name,
          version: det.version,
          status: 'error',
          message: err instanceof Error ? err.message : String(err),
          queries: [],
          vulns: [],
        };
      }
      state.vulnReports[det.id] = report;
      await publish(state);
    }),
  );
}

async function updateBadge(state: AnalysisState): Promise<void> {
  const vulnCount = Object.values(state.vulnReports).reduce((n, r) => n + r.vulns.length, 0);
  const text = state.status === 'done' ? String(state.technologies.length || '') : '';
  try {
    await chrome.action.setBadgeText({ tabId: state.tabId, text });
    await chrome.action.setBadgeBackgroundColor({ tabId: state.tabId, color: vulnCount ? '#c2410c' : '#334155' });
  } catch {
    // Tab may be gone.
  }
}

async function analyze(tabId: number, url: string, probeHeaders: boolean | undefined): Promise<void> {
  const settings = await getSettings();
  const state = baseState(tabId, url, settings);
  await publish(state);
  try {
    const withHeaders = probeHeaders ?? settings.autoHeaderProbe;
    const { signatures, plan } = await getSignatureSet();
    const { dom, main, probe, probeError, mainAvailable } = await collect(tabId, withHeaders, plan);
    // Use the URL actually observed in the frame (it may differ after client-side navigation).
    state.url = dom.url;
    state.domain = new URL(dom.url).hostname;
    state.technologies = detectTechnologies(buildSnapshot(dom, main, probe), signatures);
    state.recon = buildRecon(dom, probe);
    if (!mainAvailable) state.recon.notes.unshift('Variáveis globais da página não puderam ser lidas; detecções por versão em JavaScript ficam limitadas.');
    if (probeError) state.recon.notes.unshift(`Captura de headers falhou: ${probeError}`);
    if (dom.htmlTruncated) state.recon.notes.push('HTML maior que 1 MB: apenas o início foi analisado.');
    state.status = 'correlating';
    await publish(state);

    await correlate(state, settings);
    state.status = 'done';
    state.finishedAt = new Date().toISOString();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const blocked = /cannot be scripted|Cannot access|chrome:\/\/|extensions gallery|Missing host permission|permission/i.test(message);
    state.status = blocked ? 'unsupported' : 'error';
    state.error = blocked
      ? 'O navegador não permite que extensões analisem esta página (página protegida ou sem permissão). Clique no ícone da extensão novamente para conceder acesso à aba.'
      : `Falha na análise: ${message}`;
    state.finishedAt = new Date().toISOString();
  }
  await publish(state);
  await updateBadge(state);
}

function run(tabId: number, job: () => Promise<void>): Promise<void> {
  const p = job().finally(() => {
    if (running.get(tabId) === p) running.delete(tabId);
  });
  running.set(tabId, p);
  return p;
}

async function handleAnalyze(msg: Extract<PopupRequest, { type: 'analyze' }>): Promise<void> {
  const { tabId } = msg;
  let tab: chrome.tabs.Tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch {
    return;
  }
  const settings = await getSettings();
  const url = tab.url ?? tab.pendingUrl ?? '';
  const support = checkUrlSupport(url);
  if (!support.ok) {
    const state = baseState(tabId, url, settings);
    state.status = 'unsupported';
    state.error = support.reason;
    state.finishedAt = state.startedAt;
    broadcast(state);
    return;
  }

  if (running.has(tabId) && !msg.force && !msg.probeHeaders) {
    const current = await loadAnalysis(tabId);
    if (current) broadcast(current);
    return;
  }
  if (!msg.force && !msg.probeHeaders) {
    const cached = await loadAnalysis(tabId);
    // A finished analysis of the same URL is reused; a stale "in progress" one (worker restarted) is redone.
    if (cached && cached.url === url && (cached.status === 'done' || cached.status === 'unsupported')) {
      broadcast(cached);
      return;
    }
  }
  if (running.has(tabId)) await running.get(tabId)!.catch(() => undefined);
  await run(tabId, () => analyze(tabId, url, msg.probeHeaders || undefined));
}

async function handleRetry(tabId: number): Promise<void> {
  const state = await loadAnalysis(tabId);
  if (!state || running.has(tabId)) return;
  const failed = new Set(Object.values(state.vulnReports).filter((r) => r.status === 'error' || r.message?.startsWith('Consulta parcial')).map((r) => r.techId));
  if (!failed.size) {
    broadcast(state);
    return;
  }
  await run(tabId, async () => {
    const settings = await getSettings();
    state.status = 'correlating';
    state.cveLookupEnabled = settings.cveLookup;
    await correlate(state, settings, failed);
    state.status = 'done';
    state.finishedAt = new Date().toISOString();
    await publish(state);
    await updateBadge(state);
  });
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'techrecon-popup' || port.sender?.id !== chrome.runtime.id) return;
  let subscribedTab: number | null = null;
  port.onMessage.addListener((msg: PopupRequest) => {
    if (!msg || typeof msg !== 'object' || typeof msg.tabId !== 'number') return;
    if (subscribedTab !== msg.tabId) {
      if (subscribedTab !== null) ports.get(subscribedTab)?.delete(port);
      subscribedTab = msg.tabId;
      if (!ports.has(msg.tabId)) ports.set(msg.tabId, new Set());
      ports.get(msg.tabId)!.add(port);
    }
    if (msg.type === 'analyze') void handleAnalyze(msg);
    else if (msg.type === 'retry-cve') void handleRetry(msg.tabId);
  });
  port.onDisconnect.addListener(() => {
    if (subscribedTab !== null) ports.get(subscribedTab)?.delete(port);
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void deleteAnalysis(tabId);
  ports.delete(tabId);
});

chrome.runtime.onInstalled.addListener(() => {
  void cache.prune(7 * 24 * 3600_000);
});
