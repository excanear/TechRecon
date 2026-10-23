import { useCallback, useEffect, useRef, useState } from 'react';
import type { AggregatedTech } from '../crawler/aggregate';
import type { AssetRecord, PageRecord } from '../crawler/types';
import { hasScopePermissions, requestScopePermissions } from '../scope/permissions';
import { sanitizeScope, scopeFromSeeds } from '../scope/scope';
import type { ScanSession, ScopeConfig, TechCveRecord, VulnFindingRecord } from '../scan/types';
import type { ScanEvent, ScanRequest } from '../background/scanChannel';

export interface Inventory {
  technologies: AggregatedTech[];
  pages: PageRecord[];
  assets: AssetRecord[];
  techCve: TechCveRecord[];
  /** Unique vulnerabilities of the site, most urgent first. */
  vulnerabilities: VulnFindingRecord[];
}

export function useScan() {
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [inventories, setInventories] = useState<Record<string, Inventory>>({});
  const [error, setError] = useState<string | null>(null);
  const portRef = useRef<chrome.runtime.Port | null>(null);

  const getPort = useCallback(() => {
    if (portRef.current) return portRef.current;
    const port = chrome.runtime.connect({ name: 'techrecon-scan' });
    port.onMessage.addListener((event: ScanEvent) => {
      if (event.type === 'sessions') setSessions(event.sessions);
      else if (event.type === 'session') {
        setSessions((prev) => {
          const i = prev.findIndex((s) => s.id === event.session.id);
          if (i === -1) return [event.session, ...prev];
          const next = [...prev];
          next[i] = event.session;
          return next;
        });
      } else if (event.type === 'inventory') {
        setInventories((prev) => ({ ...prev, [event.sessionId]: { technologies: event.technologies, pages: event.pages, assets: event.assets, techCve: event.techCve, vulnerabilities: event.vulnerabilities } }));
      } else if (event.type === 'error') setError(event.message);
    });
    port.onDisconnect.addListener(() => {
      if (portRef.current === port) portRef.current = null;
    });
    portRef.current = port;
    return port;
  }, []);

  const send = useCallback(
    (msg: ScanRequest) => {
      try {
        getPort().postMessage(msg);
      } catch {
        portRef.current = null;
        getPort().postMessage(msg);
      }
    },
    [getPort],
  );

  useEffect(() => {
    send({ type: 'list' });
    return () => {
      portRef.current?.disconnect();
      portRef.current = null;
    };
  }, [send]);

  const startScan = useCallback(
    async (label: string, seeds: string[], overrides: Partial<ScopeConfig>, statement: string): Promise<string | null> => {
      setError(null);
      const scope = sanitizeScope(scopeFromSeeds(seeds, overrides));
      if (scope.seeds.length === 0) {
        setError('Informe ao menos uma URL inicial válida (http/https).');
        return null;
      }
      // Host permission must be requested from this user gesture (the click that called startScan).
      // Skip the prompt when access was already granted (e.g. a repeat scan of the same scope).
      const already = await hasScopePermissions(scope).catch(() => false);
      const granted = already || (await requestScopePermissions(scope).catch(() => false));
      if (!granted) {
        setError('Permissão de acesso aos domínios do escopo não concedida. A varredura precisa dela.');
        return null;
      }
      send({ type: 'create', label, scope, statement });
      // The background assigns the id; find it on the next sessions update by label+createdAt.
      return new Promise((resolve) => {
        const port = getPort();
        const listener = (event: ScanEvent) => {
          if (event.type === 'session' && event.session.label === label.trim().slice(0, 120)) {
            port.onMessage.removeListener(listener);
            send({ type: 'start', sessionId: event.session.id });
            resolve(event.session.id);
          }
        };
        port.onMessage.addListener(listener);
      });
    },
    [send, getPort],
  );

  const abortScan = useCallback((sessionId: string) => send({ type: 'abort', sessionId }), [send]);
  const deleteScan = useCallback((sessionId: string) => send({ type: 'delete', sessionId }), [send]);
  const loadInventory = useCallback((sessionId: string) => send({ type: 'inventory', sessionId }), [send]);

  return { sessions, inventories, error, startScan, abortScan, deleteScan, loadInventory, clearError: () => setError(null) };
}
