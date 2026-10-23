// Minimal HTTP layer for vulnerability sources: throttling, timeouts, bounded retries and
// error messages that say what actually happened (never a fabricated success).

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;
export type Sleep = (ms: number) => Promise<void>;

export const realSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class SourceError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly retryable = false,
  ) {
    super(message);
    this.name = 'SourceError';
  }
}

/** Serializes calls and keeps at least `intervalMs` between their starts. */
export class Throttle {
  private chain: Promise<void> = Promise.resolve();
  private nextAt = 0;

  constructor(
    public intervalMs: number,
    private readonly sleep: Sleep = realSleep,
  ) {}

  schedule<T>(fn: () => Promise<T>): Promise<T> {
    const turn = this.chain.then(async () => {
      const wait = this.nextAt - Date.now();
      if (wait > 0) await this.sleep(wait);
      this.nextAt = Date.now() + this.intervalMs;
    });
    this.chain = turn.catch(() => undefined);
    return turn.then(fn);
  }
}

export interface RequestOptions {
  fetch: FetchLike;
  throttle?: Throttle;
  sleep?: Sleep;
  timeoutMs?: number;
  retries?: number;
  retryDelayMs?: number;
  /** Source name used in error messages. */
  label: string;
  /** Extra explanation for HTTP 403/429 (rate limiting). */
  rateLimitHint?: string;
}

function describeStatus(status: number, opts: RequestOptions): { message: string; retryable: boolean } {
  if (status === 403 || status === 429) {
    return {
      message: `${opts.label}: limite de requisições atingido (HTTP ${status}).${opts.rateLimitHint ? ` ${opts.rateLimitHint}` : ''}`,
      retryable: true,
    };
  }
  if (status >= 500) return { message: `${opts.label}: serviço indisponível (HTTP ${status}).`, retryable: true };
  if (status === 404) return { message: `${opts.label}: recurso não encontrado (HTTP 404).`, retryable: false };
  return { message: `${opts.label}: resposta inesperada (HTTP ${status}).`, retryable: false };
}

export async function requestJson<T>(url: string, init: RequestInit, opts: RequestOptions): Promise<T> {
  const sleep = opts.sleep ?? realSleep;
  const retries = opts.retries ?? 1;
  let lastError: SourceError | null = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await sleep((opts.retryDelayMs ?? 6000) * attempt);
    const run = async (): Promise<T> => {
      let response: Response;
      try {
        response = await opts.fetch(url, { ...init, signal: AbortSignal.timeout(opts.timeoutMs ?? 30000) });
      } catch (err) {
        const name = err instanceof Error ? err.name : '';
        if (name === 'TimeoutError' || name === 'AbortError') {
          throw new SourceError(`${opts.label}: tempo de resposta esgotado.`, undefined, true);
        }
        throw new SourceError(`${opts.label}: falha de rede (${err instanceof Error ? err.message : 'erro desconhecido'}).`, undefined, true);
      }
      if (!response.ok) {
        const { message, retryable } = describeStatus(response.status, opts);
        throw new SourceError(message, response.status, retryable);
      }
      try {
        return (await response.json()) as T;
      } catch {
        throw new SourceError(`${opts.label}: resposta não é JSON válido.`);
      }
    };
    try {
      return await (opts.throttle ? opts.throttle.schedule(run) : run());
    } catch (err) {
      lastError = err instanceof SourceError ? err : new SourceError(`${opts.label}: ${String(err)}`);
      if (!lastError.retryable) break;
    }
  }
  throw lastError ?? new SourceError(`${opts.label}: erro desconhecido.`);
}
