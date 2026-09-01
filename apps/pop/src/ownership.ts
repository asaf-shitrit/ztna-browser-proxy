import type { Redis } from 'ioredis';

/**
 * Which POP currently holds the tunnel for a given connector.
 *
 * A connector dials one POP and holds a single HTTP/2 session to it, so only
 * that instance can open streams into its network. With clients and connectors
 * each attaching to whichever POP is closest, the POP a user lands on is
 * frequently NOT the one holding the connector they need — so ownership has to
 * be discoverable.
 *
 * Ownership is a lease, not a fact: it is published with a TTL and renewed
 * while the session is alive. If a POP dies, the key expires on its own and the
 * connector's reconnect re-publishes it elsewhere. Nothing has to notice the
 * failure or clean up after it.
 */
export interface OwnershipRegistry {
  /** Publish that this POP holds `connectorId`, and keep the lease renewed. */
  claim(connectorId: string): Promise<void>;
  /** Drop the lease, but only if this POP still holds it. */
  release(connectorId: string): Promise<void>;
  /** Mesh address of the owning POP, or null if nobody holds it. */
  lookup(connectorId: string): Promise<string | null>;
  close(): void;
}

const OWNER_PREFIX = 'ztna:owner:';
export const LEASE_TTL_SECONDS = 30;
export const RENEW_INTERVAL_MS = 10_000;

/**
 * Single-POP deployments. Every connector is local, so a lookup that gets here
 * means the connector is genuinely absent.
 */
export class LocalOwnership implements OwnershipRegistry {
  async claim(): Promise<void> {}
  async release(): Promise<void> {}
  async lookup(): Promise<string | null> {
    return null;
  }
  close(): void {}
}

export class RedisOwnership implements OwnershipRegistry {
  readonly #timers = new Map<string, NodeJS.Timeout>();

  constructor(
    private readonly redis: Redis,
    /** How peers reach this POP's mesh listener, e.g. `pop-2.internal:8446`. */
    private readonly selfAddress: string,
    private readonly onError: (err: Error) => void = () => {},
  ) {}

  async claim(connectorId: string): Promise<void> {
    await this.#publish(connectorId);

    this.#timers.get(connectorId)?.unref();
    clearInterval(this.#timers.get(connectorId));

    const timer = setInterval(() => {
      void this.renew(connectorId).catch((err: unknown) => {
        this.onError(err instanceof Error ? err : new Error(String(err)));
      });
    }, RENEW_INTERVAL_MS);
    timer.unref();
    this.#timers.set(connectorId, timer);
  }

  async release(connectorId: string): Promise<void> {
    clearInterval(this.#timers.get(connectorId));
    this.#timers.delete(connectorId);

    // Compare-and-delete: a connector that has already reconnected elsewhere
    // has had its lease overwritten by the new owner, and this POP must not
    // delete it on the way out.
    await this.redis.eval(
      `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`,
      1,
      OWNER_PREFIX + connectorId,
      this.selfAddress,
    );
  }

  /**
   * Extend the lease, but ONLY if it is still ours (or has lapsed with nobody
   * else holding it).
   *
   * An unconditional SET here is a real failover bug: when a connector moves to
   * another POP, this POP may not have noticed its socket close yet, and the
   * next renew tick would stamp its own address over the new owner's lease.
   * Clients would then be routed here, to a POP with no live session for that
   * connector, and get a 502 until the next renew — for up to a full renew
   * interval after a successful failover.
   */
  async renew(connectorId: string): Promise<void> {
    await this.redis.eval(
      `local current = redis.call('get', KEYS[1])
       if current == false or current == ARGV[1] then
         return redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[2])
       end
       return 0`,
      1,
      OWNER_PREFIX + connectorId,
      this.selfAddress,
      String(LEASE_TTL_SECONDS),
    );
  }

  async lookup(connectorId: string): Promise<string | null> {
    return this.redis.get(OWNER_PREFIX + connectorId);
  }

  close(): void {
    for (const timer of this.#timers.values()) clearInterval(timer);
    this.#timers.clear();
  }

  async #publish(connectorId: string): Promise<void> {
    await this.redis.set(
      OWNER_PREFIX + connectorId,
      this.selfAddress,
      'EX',
      LEASE_TTL_SECONDS,
    );
  }
}
