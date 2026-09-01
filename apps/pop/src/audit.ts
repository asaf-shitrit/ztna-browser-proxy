import type { Decision, Identity } from '@ztna/policy';

/**
 * Every authorization decision produces exactly one audit record. In a ZTNA
 * system the audit trail is a product feature, not debug output: it is the only
 * place that answers "who reached what, when, and under which rule".
 */

/**
 * What actually happened to the connection, as distinct from what policy
 * decided. An allowed connection that could not be established is NOT a
 * successful access, and conflating the two would silently inflate any count
 * of `effect=allow` in the audit trail.
 */
export type AccessOutcome = 'established' | 'blocked' | 'unavailable';

export interface AuditRecord {
  ts: string;
  event: 'access';
  effect: 'allow' | 'deny';
  outcome: AccessOutcome;
  reason: string;
  sub?: string | undefined;
  email?: string | undefined;
  groups?: string[] | undefined;
  host: string;
  port: number;
  appId?: string | undefined;
  ruleId?: string | undefined;
  connectorId?: string | undefined;
  status?: number | undefined;
  bytesUp?: number | undefined;
  bytesDown?: number | undefined;
  durationMs?: number | undefined;
}

const RING_SIZE = 500;

/**
 * Durable backing for the audit trail. The in-memory ring is fine for one POP,
 * but the records vanish on restart and are invisible to sibling instances —
 * so the store is pluggable.
 */
export interface AuditSink {
  append(record: AuditRecord): void;
  recent(limit: number): Promise<AuditRecord[]>;
}

export class AuditLog {
  #ring: AuditRecord[] = [];
  #sink: AuditSink | undefined;

  constructor(sink?: AuditSink) {
    this.#sink = sink;
  }

  record(entry: Omit<AuditRecord, 'ts' | 'event'>): AuditRecord {
    const record: AuditRecord = {
      ts: new Date().toISOString(),
      event: 'access',
      ...entry,
    };

    // stdout is always written: it is the trail that survives Redis being
    // unavailable, and what a log shipper collects.
    console.log(JSON.stringify(record));

    this.#ring.push(record);
    if (this.#ring.length > RING_SIZE) this.#ring.shift();
    this.#sink?.append(record);

    return record;
  }

  decision(
    identity: Identity | undefined,
    target: { host: string; port: number },
    decision: Decision,
    extra: Partial<AuditRecord> & { outcome: AccessOutcome },
  ): AuditRecord {
    return this.record({
      effect: decision.effect,
      reason: decision.reason,
      sub: identity?.sub,
      email: identity?.email,
      groups: identity?.groups,
      host: target.host,
      port: target.port,
      appId: decision.appId,
      ruleId: decision.ruleId,
      connectorId: decision.connectorId,
      ...extra,
    });
  }

  async recent(limit = 100): Promise<AuditRecord[]> {
    if (this.#sink) {
      try {
        return await this.#sink.recent(limit);
      } catch {
        // Fall back to the local ring rather than failing the request.
      }
    }
    return this.#ring.slice(-limit).reverse();
  }
}

export function log(level: 'info' | 'warn' | 'error', msg: string, extra: object = {}): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra }));
}
