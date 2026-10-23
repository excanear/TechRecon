import 'fake-indexeddb/auto';
import { beforeEach, describe, expect, it } from 'vitest';
import { closeDb } from '../src/db';
import {
  AuthorizationError,
  assertRunnable,
  authorizeSession,
  createSession,
  deleteSession,
  isAuthorized,
  listSessions,
  loadSession,
  saveSession,
} from '../src/scan/session';
import { put } from '../src/db';
import { scopeFromSeeds } from '../src/scope/scope';

// fake-indexeddb gives tests a real IndexedDB; reset the cached connection and delete the db between tests.
beforeEach(async () => {
  await closeDb();
  await new Promise<void>((resolve) => {
    const req = indexedDB.deleteDatabase('techrecon');
    req.onsuccess = req.onerror = () => resolve();
  });
});

const scope = () => scopeFromSeeds(['https://example.com/']);

describe('authorization gate', () => {
  it('a new session is a draft and not runnable', () => {
    const s = createSession('Test', scope());
    expect(s.status).toBe('draft');
    expect(isAuthorized(s.authorization)).toBe(false);
    expect(() => assertRunnable(s)).toThrow(AuthorizationError);
  });

  it('authorizing requires a non-empty statement', () => {
    const s = createSession('Test', scope());
    expect(() => authorizeSession(s, '   ')).toThrow(AuthorizationError);
    const authorized = authorizeSession(s, 'Engagement ACME-2026, cliente autorizou.');
    expect(authorized.status).toBe('authorized');
    expect(authorized.authorization.at).not.toBe('');
    expect(() => assertRunnable(authorized)).not.toThrow();
  });

  it('refuses to run without seeds even if authorized', () => {
    const s = authorizeSession(createSession('Test', { ...scope(), seeds: [] }), 'ok');
    expect(() => assertRunnable(s)).toThrow(/URL inicial/);
  });
});

describe('session persistence', () => {
  it('saves, loads and lists sessions newest-first', async () => {
    const a = await saveSession(createSession('A', scope()));
    await new Promise((r) => setTimeout(r, 2));
    const b = await saveSession(createSession('B', scope()));
    expect(await loadSession(a.id)).toMatchObject({ id: a.id, label: 'A' });
    const list = await listSessions();
    expect(list.map((s) => s.id)).toEqual([b.id, a.id]);
  });

  it('deleting a session removes its pages and findings', async () => {
    const s = await saveSession(createSession('A', scope()));
    await put('pages', { key: `${s.id}:1`, sessionId: s.id, url: 'https://example.com/' });
    await put('techFindings', { key: `${s.id}:jquery`, sessionId: s.id, name: 'jQuery' });
    await deleteSession(s.id);
    expect(await loadSession(s.id)).toBeUndefined();
    const { getAllByIndex } = await import('../src/db');
    expect(await getAllByIndex('pages', 'sessionId', s.id)).toEqual([]);
    expect(await getAllByIndex('techFindings', 'sessionId', s.id)).toEqual([]);
  });

  it('clamps the scope when creating a session', () => {
    const s = createSession('x'.repeat(500), { ...scope(), maxPages: 9_999_999, requestsPerSecond: 9999 });
    expect(s.label.length).toBeLessThanOrEqual(120);
    expect(s.scope.maxPages).toBeLessThanOrEqual(5000);
    expect(s.scope.requestsPerSecond).toBeLessThanOrEqual(20);
  });
});
