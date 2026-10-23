// ScanSession lifecycle and persistence. The authorization gate lives here: a session cannot
// move to a runnable state without a recorded, explicit authorization acknowledgment.

import { deleteByIndex, del, getAll, get, put } from '../db';
import { sanitizeScope } from '../scope/scope';
import { emptyCounters, type Authorization, type ScanSession, type ScopeConfig } from './types';

export class AuthorizationError extends Error {
  constructor() {
    super('A varredura exige autorização explícita do alvo antes de iniciar.');
    this.name = 'AuthorizationError';
  }
}

function newId(): string {
  // crypto.randomUUID exists in service workers and modern browsers; fall back for older runtimes.
  try {
    return crypto.randomUUID();
  } catch {
    return `scan-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  }
}

export function createSession(label: string, scope: ScopeConfig): ScanSession {
  return {
    id: newId(),
    label: label.trim().slice(0, 120) || 'Scan',
    scope: sanitizeScope(scope),
    authorization: { acknowledged: false, statement: '', at: '' },
    status: 'draft',
    counters: emptyCounters(),
    createdAt: new Date().toISOString(),
  };
}

export function isAuthorized(auth: Authorization): boolean {
  return auth.acknowledged === true && auth.statement.trim().length > 0;
}

/** Records authorization and promotes a draft to "authorized" (ready to run). */
export function authorizeSession(session: ScanSession, statement: string): ScanSession {
  const trimmed = statement.trim().slice(0, 500);
  if (!trimmed) throw new AuthorizationError();
  return {
    ...session,
    authorization: { acknowledged: true, statement: trimmed, at: new Date().toISOString() },
    status: session.status === 'draft' ? 'authorized' : session.status,
  };
}

/** Guard: throws unless the session is authorized. Called before any fetch is scheduled. */
export function assertRunnable(session: ScanSession): void {
  if (!isAuthorized(session.authorization)) throw new AuthorizationError();
  if (session.scope.seeds.length === 0) throw new Error('Defina ao menos uma URL inicial no escopo.');
}

export async function saveSession(session: ScanSession): Promise<ScanSession> {
  await put('sessions', session);
  return session;
}

export function loadSession(id: string): Promise<ScanSession | undefined> {
  return get('sessions', id);
}

export async function listSessions(): Promise<ScanSession[]> {
  const sessions = await getAll<ScanSession>('sessions');
  return sessions.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** Removes a session and all of its pages, assets and findings. */
export async function deleteSession(id: string): Promise<void> {
  await Promise.all([
    deleteByIndex('pages', 'sessionId', id),
    deleteByIndex('assets', 'sessionId', id),
    deleteByIndex('techFindings', 'sessionId', id),
    deleteByIndex('misconfigFindings', 'sessionId', id),
  ]);
  await del('sessions', id);
}
