import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { Identity } from '@ztna/policy';

/**
 * Proxy sessions.
 *
 * Chrome caches proxy credentials for the lifetime of a browser session and
 * offers no way to clear them programmatically. Handing it a rotating JWT as
 * the proxy password would therefore produce stale-credential 407 loops the
 * moment the token refreshed. Instead the POP mints a stable opaque secret and
 * resolves it to the live identity on every CONNECT, which also keeps the
 * bearer token out of the proxy path entirely.
 *
 * Because the secret is stable, revocation must happen here — sign-out deletes
 * the session server-side rather than relying on the browser to forget.
 */

export interface Session {
  proxyUser: string;
  proxySecret: string;
  identity: Identity;
  expiresAt: number;
}

/**
 * Async so a networked backend (Redis) can implement it. The memory store
 * resolves immediately; the cost is one already-resolved promise per CONNECT.
 */
export interface SessionStore {
  create(identity: Identity, ttlMs: number): Promise<Session>;
  resolve(proxyUser: string, proxySecret: string): Promise<Session | undefined>;
  revokeBySubject(sub: string): Promise<number>;
  size(): Promise<number>;
}

export class MemorySessionStore implements SessionStore {
  readonly #byUser = new Map<string, Session>();

  async create(identity: Identity, ttlMs: number): Promise<Session> {
    // One live session per subject: re-authenticating replaces the old one so
    // a stale secret cannot outlive a sign-out.
    await this.revokeBySubject(identity.sub);

    const session: Session = {
      proxyUser: `u-${randomBytes(9).toString('base64url')}`,
      proxySecret: randomBytes(32).toString('base64url'),
      identity,
      expiresAt: Date.now() + ttlMs,
    };
    this.#byUser.set(session.proxyUser, session);
    return session;
  }

  async resolve(proxyUser: string, proxySecret: string): Promise<Session | undefined> {
    const session = this.#byUser.get(proxyUser);
    if (!session) return undefined;

    if (session.expiresAt <= Date.now()) {
      this.#byUser.delete(proxyUser);
      return undefined;
    }

    // Constant-time compare: the secret is a bearer credential, and a timing
    // oracle here would let an attacker recover it byte by byte.
    if (!constantTimeEquals(session.proxySecret, proxySecret)) return undefined;

    return session;
  }

  async revokeBySubject(sub: string): Promise<number> {
    let removed = 0;
    for (const [user, session] of this.#byUser) {
      if (session.identity.sub === sub) {
        this.#byUser.delete(user);
        removed += 1;
      }
    }
    return removed;
  }

  async size(): Promise<number> {
    return this.#byUser.size;
  }
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
