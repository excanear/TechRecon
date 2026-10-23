// Scan control channel: a separate port ("techrecon-scan") the scan UI connects to. It is kept
// apart from the per-tab analysis channel so the existing single-page flow is untouched.

import { getAllByIndex } from '../db';
import { correlateDetection } from '../cve/correlate';
import { enrichVulns } from '../cve/enrich';
import { getSignatureSet } from '../fingerprinting/registry';
import { getSettings } from '../storage';
import type { AggregatedTech } from '../crawler/aggregate';
import type { AssetRecord, PageRecord } from '../crawler/types';
import { runScan, type ScanRunHandle } from '../scan/runner';
import { authorizeSession, createSession, deleteSession, listSessions, loadSession, saveSession } from '../scan/session';
import type { ScanSession, ScopeConfig, TechCveRecord, VulnFindingRecord } from '../scan/types';
import { correlationContext, enrichmentContext } from './intel';
import { offscreenFetch } from './offscreenBridge';
import { closeOffscreen } from './offscreenBridge';

export type ScanRequest =
  | { type: 'list' }
  | { type: 'create'; label: string; scope: ScopeConfig; statement: string }
  | { type: 'start'; sessionId: string }
  | { type: 'abort'; sessionId: string }
  | { type: 'delete'; sessionId: string }
  | { type: 'inventory'; sessionId: string };

export type ScanEvent =
  | { type: 'sessions'; sessions: ScanSession[] }
  | { type: 'session'; session: ScanSession }
  | {
      type: 'inventory';
      sessionId: string;
      technologies: AggregatedTech[];
      pages: PageRecord[];
      assets: AssetRecord[];
      techCve: TechCveRecord[];
      vulnerabilities: VulnFindingRecord[];
    }
  | { type: 'error'; message: string };

const subscribers = new Set<chrome.runtime.Port>();
const active = new Map<string, ScanRunHandle>();

function broadcast(event: ScanEvent): void {
  for (const port of subscribers) {
    try {
      port.postMessage(event);
    } catch {
      // Closed.
    }
  }
}

async function sendSessions(port: chrome.runtime.Port): Promise<void> {
  port.postMessage({ type: 'sessions', sessions: await listSessions() } satisfies ScanEvent);
}

async function sendInventory(port: chrome.runtime.Port, sessionId: string): Promise<void> {
  const [technologies, pages, assets, techCve, vulnerabilities] = await Promise.all([
    getAllByIndex<AggregatedTech>('techFindings', 'sessionId', sessionId),
    getAllByIndex<PageRecord>('pages', 'sessionId', sessionId),
    getAllByIndex<AssetRecord>('assets', 'sessionId', sessionId),
    getAllByIndex<TechCveRecord>('techCve', 'sessionId', sessionId),
    getAllByIndex<VulnFindingRecord>('vulnFindings', 'sessionId', sessionId),
  ]);
  vulnerabilities.sort((a, b) => a.rank - b.rank);
  port.postMessage({ type: 'inventory', sessionId, technologies, pages, assets, techCve, vulnerabilities } satisfies ScanEvent);
}

async function startSession(sessionId: string): Promise<void> {
  if (active.has(sessionId)) return;
  const session = await loadSession(sessionId);
  if (!session) {
    broadcast({ type: 'error', message: 'Sessão não encontrada.' });
    return;
  }
  const [{ signatures }, settings] = await Promise.all([getSignatureSet(), getSettings()]);
  if (active.has(sessionId)) return;
  const correlation = settings.cveLookup ? correlationContext(settings) : null;
  const handle = runScan(session, {
    fetcher: offscreenFetch,
    signatures,
    cve: correlation
      ? { correlate: (tech) => correlateDetection(tech, correlation), enrich: (vulns) => enrichVulns(vulns, enrichmentContext()) }
      : undefined,
    onUpdate: (s) => broadcast({ type: 'session', session: s }),
  });
  active.set(sessionId, handle);
  handle.promise.finally(() => {
    active.delete(sessionId);
    if (active.size === 0) void closeOffscreen();
    void sendInventoryToAll(sessionId);
  });
}

async function sendInventoryToAll(sessionId: string): Promise<void> {
  for (const port of subscribers) await sendInventory(port, sessionId).catch(() => undefined);
}

async function handle(port: chrome.runtime.Port, msg: ScanRequest): Promise<void> {
  switch (msg.type) {
    case 'list':
      await sendSessions(port);
      break;
    case 'create': {
      const session = authorizeSession(createSession(msg.label, msg.scope), msg.statement);
      await saveSession(session);
      broadcast({ type: 'session', session });
      await sendSessions(port);
      break;
    }
    case 'start':
      await startSession(msg.sessionId);
      break;
    case 'abort':
      active.get(msg.sessionId)?.abort();
      break;
    case 'delete':
      active.get(msg.sessionId)?.abort();
      await deleteSession(msg.sessionId);
      await sendSessions(port);
      break;
    case 'inventory':
      await sendInventory(port, msg.sessionId);
      break;
    default:
      break;
  }
}

export function registerScanChannel(): void {
  chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== 'techrecon-scan' || port.sender?.id !== chrome.runtime.id) return;
    subscribers.add(port);
    port.onMessage.addListener((msg: ScanRequest) => {
      if (!msg || typeof msg !== 'object') return;
      handle(port, msg).catch((err) => port.postMessage({ type: 'error', message: err instanceof Error ? err.message : String(err) } satisfies ScanEvent));
    });
    port.onDisconnect.addListener(() => subscribers.delete(port));
  });
}
