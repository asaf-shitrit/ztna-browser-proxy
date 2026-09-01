/**
 * Fixed-window rate limiter keyed by caller.
 *
 * The proxy secret is the credential that authorizes access to every app a
 * user can reach, and the 407 challenge is an unauthenticated endpoint exposed
 * to the internet. Without a limit, an attacker can guess against it as fast as
 * the network allows, and each failure costs the POP nothing to answer. The
 * same applies to the token endpoint on the control API.
 *
 * Deliberately in-process and approximate: this is abuse control, not
 * accounting. Distributing it would mean a round trip on the hot path.
 */
export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

interface Window {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  readonly #windows = new Map<string, Window>();
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  #lastSweep = 0;

  constructor(opts: { limit: number; windowMs: number; now?: () => number }) {
    this.#limit = opts.limit;
    this.#windowMs = opts.windowMs;
    this.#now = opts.now ?? Date.now;
  }

  /** Record an attempt and report whether it is allowed. */
  hit(key: string): RateLimitDecision {
    const now = this.#now();
    this.#sweep(now);

    const window = this.#windows.get(key);
    if (!window || window.resetAt <= now) {
      this.#windows.set(key, { count: 1, resetAt: now + this.#windowMs });
      return { allowed: true, remaining: this.#limit - 1, retryAfterMs: 0 };
    }

    window.count += 1;
    if (window.count > this.#limit) {
      return { allowed: false, remaining: 0, retryAfterMs: window.resetAt - now };
    }
    return { allowed: true, remaining: this.#limit - window.count, retryAfterMs: 0 };
  }

  /** Clear a key — called after a success so honest users are never throttled. */
  clear(key: string): void {
    this.#windows.delete(key);
  }

  size(): number {
    return this.#windows.size;
  }

  /**
   * Drop expired windows. Without this the map grows once per distinct source
   * address and never shrinks, which is a slow memory leak on an
   * internet-facing listener.
   */
  #sweep(now: number): void {
    if (now - this.#lastSweep < this.#windowMs) return;
    this.#lastSweep = now;
    for (const [key, window] of this.#windows) {
      if (window.resetAt <= now) this.#windows.delete(key);
    }
  }
}
