import { Redis } from 'ioredis';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { Identity } from '@ztna/policy';
import type { Session, SessionStore } from './sessions.js';
import type { AuditRecord, AuditSink } from './audit.js';

/**
 * Redis-backed session and audit storage.
 *
 * The in-memory stores are correct for a single POP, but they make sessions
 * and the audit trail casualties of a restart, and they cannot be shared: two
 * POPs behind a load balancer would each accept only the proxy secrets they
 * happened to mint, so a user's connections would work or 407 depending on
 * which instance answered.
 *
 * Sessions live under a TTL so Redis expires them without a sweeper; the audit
 * trail is a capped list so it cannot grow without bound.
 */

const SESSION_PREFIX = 'ztna:session:';
const SUBJECT_PREFIX = 'ztna:subject:';
const AUDIT_KEY = 'ztna:audit';
const AUDIT_MAX = 5000;

export function createRedis(url: string): Redis {
  return new Redis(url, {
    maxRetriesPerRequest: 3,
    lazyConnect: false,
    // A ZTNA POP must not hang a user's connection waiting on Redis.
    connectTimeout: 3000,
  });
}

export class RedisSessionStore implements SessionStore {
  constructor(private readonly redis: Redis) {}

  async create(identity: Identity, ttlMs: number): Promise<Session> {
    // One live session per subject, mirroring the memory store: signing in
    // again must not leave the previous secret usable.
    await this.revokeBySubject(identity.sub);

    const session: Session = {
      proxyUser: `u-${randomBytes(9).toString('base64url')}`,
      proxySecret: randomBytes(32).toString('base64url'),
      identity,
      expiresAt: Date.now() + ttlMs,
    };

    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    await this.redis
      .multi()
      .set(SESSION_PREFIX + session.proxyUser, JSON.stringify(session), 'EX', ttlSeconds)
      .sadd(SUBJECT_PREFIX + identity.sub, session.proxyUser)
      .expire(SUBJECT_PREFIX + identity.sub, ttlSeconds)
      .exec();

    return session;
  }

  async resolve(proxyUser: string, proxySecret: string): Promise<Session | undefined> {
    const raw = await this.redis.get(SESSION_PREFIX + proxyUser);
    if (!raw) return undefined;

    const session = JSON.parse(raw) as Session;
    if (session.expiresAt <= Date.now()) {
      await this.redis.del(SESSION_PREFIX + proxyUser);
      return undefined;
    }

    // Constant-time: the secret is a bearer credential and a timing oracle
    // would let it be recovered byte by byte.
    if (!constantTimeEquals(session.proxySecret, proxySecret)) return undefined;

    return session;
  }

  async revokeBySubject(sub: string): Promise<number> {
    const users = await this.redis.smembers(SUBJECT_PREFIX + sub);
    if (users.length === 0) return 0;

    await this.redis
      .multi()
      .del(...users.map((u: string) => SESSION_PREFIX + u))
      .del(SUBJECT_PREFIX + sub)
      .exec();

    return users.length;
  }

  async size(): Promise<number> {
    // Approximate by design: SCAN over a live keyspace is not a snapshot, and
    // an exact count is not worth blocking Redis with KEYS.
    let cursor = '0';
    let total = 0;
    do {
      const [next, found] = await this.redis.scan(cursor, 'MATCH', `${SESSION_PREFIX}*`, 'COUNT', 500);
      cursor = next;
      total += found.length;
    } while (cursor !== '0');
    return total;
  }
}

export class RedisAuditSink implements AuditSink {
  constructor(private readonly redis: Redis) {}

  append(record: AuditRecord): void {
    // Fire-and-forget: an audit write must never delay or fail a user's
    // connection. Failures are logged, and stdout remains the durable trail.
    void this.redis
      .multi()
      .lpush(AUDIT_KEY, JSON.stringify(record))
      .ltrim(AUDIT_KEY, 0, AUDIT_MAX - 1)
      .exec()
      .catch((err: unknown) => {
        console.log(
          JSON.stringify({
            level: 'warn',
            msg: 'audit persist failed',
            error: err instanceof Error ? err.message : String(err),
          }),
        );
      });
  }

  async recent(limit: number): Promise<AuditRecord[]> {
    const raw = await this.redis.lrange(AUDIT_KEY, 0, limit - 1);
    return raw.map((r: string) => JSON.parse(r) as AuditRecord);
  }
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
