import { useCallback, useEffect, useRef, useState } from 'react';
import type { DatasetEvent, DatasetRequest } from '../background/datasetChannel';
import type { WappalyzerStatus } from '../fingerprinting/registry';

/** Status and control of the optional Wappalyzer dataset, over the "techrecon-dataset" port. */
export function useDataset() {
  const portRef = useRef<chrome.runtime.Port | null>(null);
  const [status, setStatus] = useState<WappalyzerStatus | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const port = chrome.runtime.connect({ name: 'techrecon-dataset' });
    portRef.current = port;
    port.onMessage.addListener((event: DatasetEvent) => {
      if (event.type === 'status') {
        setStatus(event.status);
        setProgress(null);
      } else if (event.type === 'progress') {
        setProgress({ done: event.done, total: event.total });
      } else if (event.type === 'error') {
        setError(event.message);
      }
    });
    port.postMessage({ type: 'status' } satisfies DatasetRequest);
    return () => {
      portRef.current = null;
      port.disconnect();
    };
  }, []);

  const send = useCallback((msg: DatasetRequest) => portRef.current?.postMessage(msg), []);

  const install = useCallback(() => {
    setError(null);
    setProgress({ done: 0, total: 1 });
    send({ type: 'install' });
  }, [send]);

  const remove = useCallback(() => {
    setError(null);
    send({ type: 'remove' });
  }, [send]);

  return { status, progress, error, install, remove };
}
