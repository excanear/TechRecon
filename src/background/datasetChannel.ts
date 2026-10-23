// Dataset control channel ("techrecon-dataset"): the settings view installs or removes the
// optional Wappalyzer dataset through it and receives download progress.

import { installWappalyzer, removeWappalyzer, wappalyzerStatus, type WappalyzerStatus } from '../fingerprinting/registry';

export type DatasetRequest = { type: 'status' } | { type: 'install' } | { type: 'remove' };

export type DatasetEvent =
  | { type: 'status'; status: WappalyzerStatus }
  | { type: 'progress'; done: number; total: number }
  | { type: 'error'; message: string };

const subscribers = new Set<chrome.runtime.Port>();
let installing: Promise<void> | null = null;

function broadcast(event: DatasetEvent): void {
  for (const port of subscribers) {
    try {
      port.postMessage(event);
    } catch {
      // Closed.
    }
  }
}

async function handle(port: chrome.runtime.Port, msg: DatasetRequest): Promise<void> {
  switch (msg.type) {
    case 'status':
      port.postMessage({ type: 'status', status: await wappalyzerStatus() } satisfies DatasetEvent);
      break;
    case 'install':
      // One download at a time; a second request just waits for the first.
      installing ??= installWappalyzer(
        (input, init) => fetch(input, init),
        (done, total) => broadcast({ type: 'progress', done, total }),
      )
        .then((status) => broadcast({ type: 'status', status }))
        .catch(async (err) => {
          broadcast({ type: 'error', message: err instanceof Error ? err.message : String(err) });
          broadcast({ type: 'status', status: await wappalyzerStatus() });
        })
        .finally(() => {
          installing = null;
        });
      await installing;
      break;
    case 'remove':
      broadcast({ type: 'status', status: await removeWappalyzer() });
      break;
    default:
      break;
  }
}

export function registerDatasetChannel(): void {
  chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== 'techrecon-dataset' || port.sender?.id !== chrome.runtime.id) return;
    subscribers.add(port);
    port.onMessage.addListener((msg: DatasetRequest) => {
      if (!msg || typeof msg !== 'object') return;
      handle(port, msg).catch((err) => port.postMessage({ type: 'error', message: err instanceof Error ? err.message : String(err) } satisfies DatasetEvent));
    });
    port.onDisconnect.addListener(() => subscribers.delete(port));
  });
}
