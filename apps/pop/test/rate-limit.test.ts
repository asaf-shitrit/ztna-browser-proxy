import { describe, it, expect } from 'vitest';
import { RateLimiter } from '../src/rate-limit.js';

/** A controllable clock, so these tests never depend on wall time. */
function clock(start = 0) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe('RateLimiter', () => {
  it('allows up to the limit and then blocks', () => {
    const c = clock();
    const rl = new RateLimiter({ limit: 3, windowMs: 1000, now: c.now });

    expect(rl.hit('1.2.3.4').allowed).toBe(true);
    expect(rl.hit('1.2.3.4').allowed).toBe(true);
    expect(rl.hit('1.2.3.4').allowed).toBe(true);

    const blocked = rl.hit('1.2.3.4');
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterMs).toBeGreaterThan(0);
  });

  it('keys independently, so one attacker cannot lock out everyone', () => {
    const c = clock();
    const rl = new RateLimiter({ limit: 1, windowMs: 1000, now: c.now });

    expect(rl.hit('attacker').allowed).toBe(true);
    expect(rl.hit('attacker').allowed).toBe(false);
    expect(rl.hit('honest-user').allowed).toBe(true);
  });

  it('recovers after the window elapses', () => {
    const c = clock();
    const rl = new RateLimiter({ limit: 1, windowMs: 1000, now: c.now });

    expect(rl.hit('k').allowed).toBe(true);
    expect(rl.hit('k').allowed).toBe(false);

    c.advance(1001);
    expect(rl.hit('k').allowed).toBe(true);
  });

  it('clears on success so honest users are never throttled', () => {
    const c = clock();
    const rl = new RateLimiter({ limit: 2, windowMs: 1000, now: c.now });

    rl.hit('k');
    rl.clear('k');
    expect(rl.hit('k').allowed).toBe(true);
    expect(rl.hit('k').allowed).toBe(true);
  });

  it('does not grow without bound as sources come and go', () => {
    const c = clock();
    const rl = new RateLimiter({ limit: 5, windowMs: 1000, now: c.now });

    for (let i = 0; i < 500; i += 1) rl.hit(`ip-${i}`);
    expect(rl.size()).toBe(500);

    // Once the windows expire, a later hit sweeps them away.
    c.advance(5000);
    rl.hit('someone-else');
    expect(rl.size()).toBe(1);
  });
});
