import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRedis, RedisSessionStore, RedisAuditSink } from '../src/redis-store.js';
import { AuditLog } from '../src/audit.js';
import type { Identity } from '@ztna/policy';
import type { Redis } from 'ioredis';

/**
 * Runs against a real Redis (docker run -p 6399:6379 redis:7-alpine).
 * Skipped when unavailable so the suite stays runnable without Docker.
 */
const URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6399';

let redis: Redis | undefined;
let available = false;

beforeAll(async () => {
  try {
    redis = createRedis(URL);
    await redis.ping();
    await redis.flushdb();
    available = true;
  } catch {
    available = false;
  }
});

afterAll(async () => {
  await redis?.quit().catch(() => undefined);
});

const alice: Identity = { sub: 'u-alice', email: 'alice@example.com', groups: ['employees'] };
const bob: Identity = { sub: 'u-bob', email: 'bob@example.com', groups: ['finance'] };

describe.runIf(process.env.SKIP_REDIS !== '1')('RedisSessionStore', () => {
  it('round-trips a session', async (ctx) => {
    if (!available) ctx.skip();
    const store = new RedisSessionStore(redis!);
    const s = await store.create(alice, 60_000);

    const found = await store.resolve(s.proxyUser, s.proxySecret);
    expect(found?.identity.sub).toBe('u-alice');
    expect(found?.identity.groups).toEqual(['employees']);
  });

  it('rejects a wrong secret', async (ctx) => {
    if (!available) ctx.skip();
    const store = new RedisSessionStore(redis!);
    const s = await store.create(alice, 60_000);
    expect(await store.resolve(s.proxyUser, 'wrong')).toBeUndefined();
  });

  it('rejects an unknown user', async (ctx) => {
    if (!available) ctx.skip();
    const store = new RedisSessionStore(redis!);
    expect(await store.resolve('nobody', 'whatever')).toBeUndefined();
  });

  it('survives a POP restart — the whole point of using Redis', async (ctx) => {
    if (!available) ctx.skip();
    const first = new RedisSessionStore(redis!);
    const s = await first.create(bob, 60_000);

    // A brand-new store instance stands in for a restarted (or sibling) POP.
    const afterRestart = new RedisSessionStore(redis!);
    const found = await afterRestart.resolve(s.proxyUser, s.proxySecret);

    expect(found?.identity.sub).toBe('u-bob');
  });

  it('revokes across instances, so sign-out is honoured everywhere', async (ctx) => {
    if (!available) ctx.skip();
    const a = new RedisSessionStore(redis!);
    const s = await a.create(alice, 60_000);

    const b = new RedisSessionStore(redis!);
    expect(await b.revokeBySubject('u-alice')).toBeGreaterThan(0);

    // The secret must stop working on the instance that minted it too.
    expect(await a.resolve(s.proxyUser, s.proxySecret)).toBeUndefined();
  });

  it('replaces the previous session when the same subject signs in again', async (ctx) => {
    if (!available) ctx.skip();
    const store = new RedisSessionStore(redis!);
    const first = await store.create(alice, 60_000);
    const second = await store.create(alice, 60_000);

    expect(await store.resolve(first.proxyUser, first.proxySecret)).toBeUndefined();
    expect(await store.resolve(second.proxyUser, second.proxySecret)).toBeDefined();
  });

  it('expires a session by TTL without a sweeper', async (ctx) => {
    if (!available) ctx.skip();
    const store = new RedisSessionStore(redis!);
    const s = await store.create(alice, 1);
    await new Promise((r) => setTimeout(r, 60));
    expect(await store.resolve(s.proxyUser, s.proxySecret)).toBeUndefined();
  });
});

describe.runIf(process.env.SKIP_REDIS !== '1')('RedisAuditSink', () => {
  it('persists records so they outlive the process that wrote them', async (ctx) => {
    if (!available) ctx.skip();
    await redis!.del('ztna:audit');

    const log = new AuditLog(new RedisAuditSink(redis!));
    log.record({
      effect: 'allow',
      outcome: 'established',
      reason: 'matched-rule',
      sub: 'u-alice',
      host: 'wiki.internal',
      port: 443,
      appId: 'wiki',
    });

    await new Promise((r) => setTimeout(r, 100));

    // A fresh AuditLog with an empty local ring must still see it.
    const afterRestart = new AuditLog(new RedisAuditSink(redis!));
    const records = await afterRestart.recent(10);
    expect(records.some((r) => r.host === 'wiki.internal' && r.sub === 'u-alice')).toBe(true);
  });

  it('falls back to the local ring when Redis is unreachable', async () => {
    const broken = createRedis('redis://127.0.0.1:6399');
    broken.disconnect();

    const log = new AuditLog(new RedisAuditSink(broken));
    log.record({
      effect: 'deny',
      outcome: 'blocked',
      reason: 'no-matching-rule',
      host: 'payroll.internal',
      port: 443,
    });

    // The user's request must never fail because the audit backend is down.
    const records = await log.recent(10);
    expect(records.some((r) => r.host === 'payroll.internal')).toBe(true);
    broken.disconnect();
  });
});

import { RedisOwnership } from '../src/ownership.js';

/**
 * Connector failover. A connector that moves to another POP must stay routed
 * there — the POP it left must not stamp its own address back over the lease
 * on its next renew tick.
 */
describe.runIf(process.env.SKIP_REDIS !== '1')('RedisOwnership', () => {
  it('publishes and resolves ownership', async (ctx) => {
    if (!available) ctx.skip();
    const a = new RedisOwnership(redis!, 'pop-a:8446');
    await a.claim('dc-pub');
    expect(await a.lookup('dc-pub')).toBe('pop-a:8446');
    a.close();
  });

  it('does not steal a lease that has moved to another POP', async (ctx) => {
    if (!available) ctx.skip();
    const a = new RedisOwnership(redis!, 'pop-a:8446');
    const b = new RedisOwnership(redis!, 'pop-b:8446');

    await a.claim('dc-move');
    await b.claim('dc-move'); // the connector reconnected to B
    expect(await a.lookup('dc-move')).toBe('pop-b:8446');

    // A has not noticed its socket close yet and renews. Before the fix this
    // overwrote B's lease and sent clients to a POP with no live session.
    await a.renew('dc-move');
    expect(await a.lookup('dc-move')).toBe('pop-b:8446');

    a.close();
    b.close();
  });

  it('reclaims its own lease if it lapsed with nobody else holding it', async (ctx) => {
    if (!available) ctx.skip();
    const a = new RedisOwnership(redis!, 'pop-a:8446');
    await redis!.del('ztna:owner:dc-lapsed');

    await a.renew('dc-lapsed');
    expect(await a.lookup('dc-lapsed')).toBe('pop-a:8446');
    a.close();
  });

  it('releases only its own lease, never the new owner\'s', async (ctx) => {
    if (!available) ctx.skip();
    const a = new RedisOwnership(redis!, 'pop-a:8446');
    const b = new RedisOwnership(redis!, 'pop-b:8446');

    await a.claim('dc-rel');
    await b.claim('dc-rel');

    // A shuts down after the connector already moved.
    await a.release('dc-rel');
    expect(await b.lookup('dc-rel')).toBe('pop-b:8446');

    a.close();
    b.close();
  });
});
