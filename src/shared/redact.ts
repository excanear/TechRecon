// Redaction of secrets before anything is stored, displayed or exported.
// TechRecon never needs full tokens, cookie values or credentials to explain a finding.

const SENSITIVE_PARAM =
  /^(?:.*(?:token|secret|passw(?:or)?d|pwd|auth|session|sess|sid|signature|sig|key|apikey|api_key|access|credential|jwt|bearer|code|nonce|ticket|hash))$/i;

const SENSITIVE_HEADER =
  /^(?:set-cookie|cookie|authorization|proxy-authorization|www-authenticate|x-csrf-token|x-xsrf-token|x-api-key|x-amz-security-token|x-auth-token)$|(?:token|secret|session|csrf|xsrf|apikey|api-key|signature)/i;

/** Long opaque strings (JWTs, base64 blobs, hex keys) that should not be reproduced verbatim. */
const OPAQUE_TOKEN = /\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}|[A-Za-z0-9+/_-]{40,}={0,2}|[a-f0-9]{32,})\b/g;

/** Keep version-like query params (they are evidence), redact anything that looks like a credential. */
export function redactUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return redactTokens(raw);
  }
  url.username = '';
  url.password = '';
  for (const [name] of [...url.searchParams]) {
    if (SENSITIVE_PARAM.test(name)) url.searchParams.set(name, 'REDACTED');
  }
  if (url.hash.length > 1) url.hash = '';
  return redactTokens(url.toString());
}

export function redactTokens(value: string): string {
  return value.replace(OPAQUE_TOKEN, (m) => `${m.slice(0, 4)}…[redacted ${m.length} chars]`);
}

export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER.test(name);
}

export function redactHeaderValue(name: string, value: string): string {
  if (isSensitiveHeader(name)) return '[redacted]';
  return redactTokens(value);
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k] = redactHeaderValue(k, v);
  return out;
}
