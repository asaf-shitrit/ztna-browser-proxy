import { describe, it, expect } from 'vitest';
import { nextRefreshAt, REFRESH_MARGIN_MS, MIN_REFRESH_DELAY_MS } from '../src/refresh.js';

const NOW = 1_000_000;

describe('nextRefreshAt', () => {
  it('refreshes a margin before expiry', () => {
    const expiry = NOW + 30 * 60_000;
    expect(nextRefreshAt(expiry, expiry + 60_000, NOW)).toBe(expiry - REFRESH_MARGIN_MS);
  });

  it('targets the token when it expires first', () => {
    const token = NOW + 10 * 60_000;
    const session = NOW + 12 * 60 * 60_000;
    expect(nextRefreshAt(token, session, NOW)).toBe(token - REFRESH_MARGIN_MS);
  });

  it('targets the session when it expires first', () => {
    const token = NOW + 12 * 60 * 60_000;
    const session = NOW + 5 * 60_000;
    expect(nextRefreshAt(token, session, NOW)).toBe(session - REFRESH_MARGIN_MS);
  });

  it('never schedules in the past for an already-expired token', () => {
    const at = nextRefreshAt(NOW - 60_000, NOW - 60_000, NOW);
    expect(at).toBe(NOW + MIN_REFRESH_DELAY_MS);
    expect(at).toBeGreaterThan(NOW);
  });

  it('never schedules in the past when expiry is inside the margin', () => {
    // Without the floor this lands before `now` and Chrome fires it instantly,
    // producing a refresh loop against the IdP.
    const at = nextRefreshAt(NOW + 10_000, NOW + 10_000, NOW);
    expect(at).toBe(NOW + MIN_REFRESH_DELAY_MS);
  });

  it('is monotonic in expiry', () => {
    const a = nextRefreshAt(NOW + 20 * 60_000, NOW + 60 * 60_000, NOW);
    const b = nextRefreshAt(NOW + 40 * 60_000, NOW + 60 * 60_000, NOW);
    expect(b).toBeGreaterThan(a);
  });
});
