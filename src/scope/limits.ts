// Politeness limits for the crawler: a per-host rate limit and a global concurrency cap.
// Both are injectable (sleep/now) so they can be unit-tested deterministically.

import type { Sleep } from '../cve/http';
import { realSleep } from '../cve/http';

/** Spaces out requests to each host so the target is never hammered. */
export class HostRateLimiter {
  private readonly nextAt = new Map<string, number>();
  private chain: Promise<void> = Promise.resolve();
  private readonly intervalMs: number;

  constructor(
    requestsPerSecond: number,
    private readonly sleep: Sleep = realSleep,
    private readonly now: () => number = Date.now,
  ) {
    this.intervalMs = Math.max(1, Math.round(1000 / Math.max(0.1, requestsPerSecond)));
  }

  /** Resolves when it is this host's turn. Calls are serialized to keep spacing exact. */
  acquire(host: string): Promise<void> {
    const turn = this.chain.then(async () => {
      const earliest = this.nextAt.get(host) ?? 0;
      const wait = earliest - this.now();
      if (wait > 0) await this.sleep(wait);
      this.nextAt.set(host, this.now() + this.intervalMs);
    });
    this.chain = turn.catch(() => undefined);
    return turn;
  }
}

/** Bounds how many page fetches run at once across the whole session. */
export class ConcurrencyLimiter {
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async acquire(): Promise<() => void> {
    if (this.active >= this.max) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    this.active++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active--;
      this.waiters.shift()?.();
    };
  }

  /** Runs `fn` while holding a slot, releasing it even on error. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    const release = await this.acquire();
    try {
      return await fn();
    } finally {
      release();
    }
  }

  get inFlight(): number {
    return this.active;
  }
}
