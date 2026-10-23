// Sanitization of untrusted text (page content, API responses) before it is stored or displayed.
// React escapes text content; these helpers additionally bound sizes, strip control
// characters and make sure only http(s) URLs can ever become links.

const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g;

export function sanitizeText(input: unknown, max = 500): string {
  if (input === null || input === undefined) return '';
  let s = typeof input === 'string' ? input : String(input);
  s = s.replace(CONTROL_CHARS, '').replace(/\s+/g, ' ').trim();
  if (s.length > max) s = `${s.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
  return s;
}

/** Multi-line variant that keeps paragraph breaks (for descriptions). */
export function sanitizeMultiline(input: unknown, max = 4000): string {
  if (input === null || input === undefined) return '';
  let s = typeof input === 'string' ? input : String(input);
  s = s
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.replace(CONTROL_CHARS, '').replace(/[ \t]+/g, ' ').trim())
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (s.length > max) s = `${s.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
  return s;
}

/** Returns a normalized http(s) URL, or null for anything else (javascript:, data:, malformed…). */
export function safeHttpUrl(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > 2048) return null;
  try {
    const u = new URL(input.trim());
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (u.username || u.password) return null;
    return u.toString();
  } catch {
    return null;
  }
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$/;

/** Advisory identifiers are displayed and used in URLs: accept only a conservative charset. */
export function safeIdentifier(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  return ID_PATTERN.test(s) ? s : null;
}

export function clampNumber(input: unknown, min: number, max: number): number | null {
  const n = typeof input === 'number' ? input : typeof input === 'string' ? Number(input) : NaN;
  if (!Number.isFinite(n)) return null;
  return Math.min(max, Math.max(min, n));
}
