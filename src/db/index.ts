// Minimal promise-based IndexedDB wrapper. Scan sessions and their pages/assets/findings
// can grow well past the chrome.storage quota, so the crawl inventory lives here. Everything
// stays in the browser profile.

export const DB_NAME = 'techrecon';
export const DB_VERSION = 1;

export interface StoreSpec {
  name: string;
  keyPath: string;
  indexes?: Array<{ name: string; keyPath: string; unique?: boolean }>;
}

/** Schema for every object store. New phases add stores here and bump DB_VERSION. */
export const STORES: StoreSpec[] = [
  { name: 'sessions', keyPath: 'id', indexes: [{ name: 'status', keyPath: 'status' }, { name: 'createdAt', keyPath: 'createdAt' }] },
  { name: 'pages', keyPath: 'key', indexes: [{ name: 'sessionId', keyPath: 'sessionId' }] },
  { name: 'assets', keyPath: 'key', indexes: [{ name: 'sessionId', keyPath: 'sessionId' }] },
  { name: 'techFindings', keyPath: 'key', indexes: [{ name: 'sessionId', keyPath: 'sessionId' }] },
  { name: 'misconfigFindings', keyPath: 'key', indexes: [{ name: 'sessionId', keyPath: 'sessionId' }] },
];

let dbPromise: Promise<IDBDatabase> | null = null;

export function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      for (const store of STORES) {
        const objectStore = db.objectStoreNames.contains(store.name)
          ? request.transaction!.objectStore(store.name)
          : db.createObjectStore(store.name, { keyPath: store.keyPath });
        for (const index of store.indexes ?? []) {
          if (!objectStore.indexNames.contains(index.name)) {
            objectStore.createIndex(index.name, index.keyPath, { unique: index.unique ?? false });
          }
        }
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB: falha ao abrir o banco.'));
  });
  return dbPromise;
}

/** Closes the cached connection (if open) and forgets it. Needed so a deleteDatabase is not blocked. */
export async function closeDb(): Promise<void> {
  const pending = dbPromise;
  dbPromise = null;
  if (pending) {
    try {
      (await pending).close();
    } catch {
      // Never opened.
    }
  }
}

function run<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(store, mode);
        const request = fn(tx.objectStore(store));
        tx.oncomplete = () => resolve(request.result);
        tx.onabort = tx.onerror = () => reject(tx.error ?? new Error(`IndexedDB: transação falhou em ${store}.`));
      }),
  );
}

export function put<T>(store: string, value: T): Promise<IDBValidKey> {
  return run(store, 'readwrite', (s) => s.put(value));
}

export function get<T>(store: string, key: IDBValidKey): Promise<T | undefined> {
  return run<T | undefined>(store, 'readonly', (s) => s.get(key) as IDBRequest<T | undefined>);
}

export function del(store: string, key: IDBValidKey): Promise<void> {
  return run(store, 'readwrite', (s) => s.delete(key) as unknown as IDBRequest<void>);
}

export function getAll<T>(store: string): Promise<T[]> {
  return run<T[]>(store, 'readonly', (s) => s.getAll() as IDBRequest<T[]>);
}

/** All records of a store whose `index` equals `value` (e.g. every page of a session). */
export function getAllByIndex<T>(store: string, index: string, value: IDBValidKey): Promise<T[]> {
  return openDb().then(
    (db) =>
      new Promise<T[]>((resolve, reject) => {
        const tx = db.transaction(store, 'readonly');
        const request = tx.objectStore(store).index(index).getAll(value) as IDBRequest<T[]>;
        tx.oncomplete = () => resolve(request.result);
        tx.onabort = tx.onerror = () => reject(tx.error ?? new Error(`IndexedDB: consulta falhou em ${store}.`));
      }),
  );
}

/** Deletes every record of a store belonging to a session (cleanup when a scan is removed). */
export async function deleteByIndex(store: string, index: string, value: IDBValidKey): Promise<number> {
  const db = await openDb();
  return new Promise<number>((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    const objectStore = tx.objectStore(store);
    const cursorRequest = objectStore.index(index).openKeyCursor(value);
    let count = 0;
    cursorRequest.onsuccess = () => {
      const cursor = cursorRequest.result;
      if (cursor) {
        objectStore.delete(cursor.primaryKey);
        count++;
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve(count);
    tx.onabort = tx.onerror = () => reject(tx.error ?? new Error(`IndexedDB: limpeza falhou em ${store}.`));
  });
}
