import { describe, it, expect } from 'vitest';
import { isOurProxy } from '../src/proxy-auth.js';
import type { PopSession } from '../src/types.js';

/**
 * `details.isProxy` says a proxy issued the challenge, not WHICH proxy. The
 * proxy secret authorizes access to every app the user can reach, so it must
 * only ever go to the POP this session was issued for.
 */
const session = {
  proxyUser: 'u-1',
  proxySecret: 's-1',
  proxy: { host: 'pop.ztna.test', port: 8443 },
} as PopSession;

describe('isOurProxy', () => {
  it('accepts a challenge from the session POP', () => {
    expect(isOurProxy({ host: 'pop.ztna.test', port: 8443 }, session)).toBe(true);
  });

  it('is case-insensitive on the host', () => {
    expect(isOurProxy({ host: 'POP.ZTNA.test', port: 8443 }, session)).toBe(true);
  });

  it('refuses a different host', () => {
    expect(isOurProxy({ host: 'evil.example.com', port: 8443 }, session)).toBe(false);
  });

  it('refuses a different port on the same host', () => {
    expect(isOurProxy({ host: 'pop.ztna.test', port: 3128 }, session)).toBe(false);
  });

  it('refuses when no challenger is reported', () => {
    expect(isOurProxy(undefined, session)).toBe(false);
  });

  it('refuses a lookalike hostname', () => {
    expect(isOurProxy({ host: 'pop.ztna.test.evil.com', port: 8443 }, session)).toBe(false);
  });
});
