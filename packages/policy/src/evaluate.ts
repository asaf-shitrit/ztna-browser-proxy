import { parse as parseYaml } from 'yaml';
import { policySchema, type PolicyDocument, type PolicyApp } from './schema.js';

export interface Identity {
  sub: string;
  email?: string | undefined;
  name?: string | undefined;
  groups: string[];
}

export interface AccessRequest {
  identity: Identity;
  host: string;
  port: number;
}

export type Effect = 'allow' | 'deny';

export interface Decision {
  effect: Effect;
  reason: DenyReason | 'matched-rule';
  appId?: string | undefined;
  ruleId?: string | undefined;
  connectorId?: string | undefined;
}

export type DenyReason = 'no-matching-app' | 'no-matching-rule';

/**
 * A compiled, immutable policy. Pure — no I/O, no clock, no network — so it is
 * cheap to evaluate on every CONNECT and trivial to test exhaustively.
 */
export class Policy {
  readonly #doc: PolicyDocument;

  private constructor(doc: PolicyDocument) {
    this.#doc = doc;
  }

  static fromDocument(doc: unknown): Policy {
    return new Policy(policySchema.parse(doc));
  }

  static fromYaml(source: string): Policy {
    return Policy.fromDocument(parseYaml(source));
  }

  get apps(): readonly PolicyApp[] {
    return this.#doc.apps;
  }

  /**
   * The single authorization decision point. Default deny: every path that is
   * not an explicit rule match returns a denial.
   */
  evaluate(request: AccessRequest): Decision {
    const app = this.#findApp(request.host, request.port);
    if (!app) {
      return { effect: 'deny', reason: 'no-matching-app' };
    }

    for (const [index, rule] of this.#doc.rules.entries()) {
      if (rule.app !== app.id) continue;
      if (!matchesIdentity(rule.allow, request.identity)) continue;

      return {
        effect: 'allow',
        reason: 'matched-rule',
        appId: app.id,
        ruleId: rule.id ?? `${rule.app}#${index}`,
        connectorId: app.connector,
      };
    }

    return { effect: 'deny', reason: 'no-matching-rule', appId: app.id };
  }

  /** Apps this identity may reach — used to build the extension's PAC script. */
  appsFor(identity: Identity): PolicyApp[] {
    return this.#doc.apps.filter((app) =>
      this.#doc.rules.some(
        (rule) => rule.app === app.id && matchesIdentity(rule.allow, identity),
      ),
    );
  }

  #findApp(host: string, port: number): PolicyApp | undefined {
    return this.#doc.apps.find(
      (app) =>
        app.ports.includes(port) &&
        app.hosts.some((pattern) => matchesHost(pattern, host)),
    );
  }
}

function matchesIdentity(
  allow: { groups?: string[] | undefined; users?: string[] | undefined },
  identity: Identity,
): boolean {
  if (allow.users?.includes(identity.sub)) return true;
  if (allow.users && identity.email && allow.users.includes(identity.email)) return true;
  if (allow.groups?.some((g) => identity.groups.includes(g))) return true;
  return false;
}

/**
 * Hostname matching. Exact is case-insensitive; `*.suffix` matches exactly one
 * additional label.
 *
 * The single-label restriction is deliberate: a greedy wildcard would let
 * `*.internal` match `evil.attacker.internal`, silently widening a rule far
 * beyond what its author intended.
 */
export function matchesHost(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();

  if (!p.startsWith('*.')) return p === h;

  const suffix = p.slice(2);
  if (!h.endsWith(`.${suffix}`)) return false;

  const label = h.slice(0, h.length - suffix.length - 1);
  // Exactly one non-empty label, no further dots.
  return label.length > 0 && !label.includes('.');
}
