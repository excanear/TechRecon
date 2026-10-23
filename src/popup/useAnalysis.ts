import { useCallback, useEffect, useRef, useState } from 'react';
import type { AnalysisState, BackgroundMessage, PopupRequest } from '../types';

type TabLookup = { tabId: number } | { error: string };

async function resolveTab(): Promise<TabLookup> {
  // ?tabId= lets the popup be opened as a page (used by the automated end-to-end test).
  const fromQuery = Number(new URLSearchParams(location.search).get('tabId'));
  if (Number.isInteger(fromQuery) && fromQuery > 0) return { tabId: fromQuery };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { error: 'Nenhuma aba ativa encontrada.' };
  return { tabId: tab.id };
}

export function useAnalysis() {
  const [tabId, setTabId] = useState<number | null>(null);
  const [state, setState] = useState<AnalysisState | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const portRef = useRef<chrome.runtime.Port | null>(null);

  const getPort = useCallback(() => {
    if (portRef.current) return portRef.current;
    const port = chrome.runtime.connect({ name: 'techrecon-popup' });
    port.onMessage.addListener((msg: BackgroundMessage) => {
      if (msg?.type === 'state') setState(msg.state);
    });
    // The service worker can be restarted by the browser; reconnect lazily on the next request.
    port.onDisconnect.addListener(() => {
      if (portRef.current === port) portRef.current = null;
    });
    portRef.current = port;
    return port;
  }, []);

  const send = useCallback(
    (msg: PopupRequest) => {
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
    let cancelled = false;
    resolveTab().then((r) => {
      if (cancelled) return;
      if ('error' in r) {
        setFatal(r.error);
        return;
      }
      setTabId(r.tabId);
      send({ type: 'analyze', tabId: r.tabId });
    });
    return () => {
      cancelled = true;
      portRef.current?.disconnect();
      portRef.current = null;
    };
  }, [send]);

  const refresh = useCallback(() => {
    if (tabId !== null) send({ type: 'analyze', tabId, force: true });
  }, [send, tabId]);

  const captureHeaders = useCallback(() => {
    if (tabId !== null) send({ type: 'analyze', tabId, force: true, probeHeaders: true });
  }, [send, tabId]);

  const retryCve = useCallback(() => {
    if (tabId !== null) send({ type: 'retry-cve', tabId });
  }, [send, tabId]);

  return { tabId, state, fatal, refresh, captureHeaders, retryCve };
}
