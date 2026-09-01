import fs from 'node:fs';
import { Policy } from '@ztna/policy';

/**
 * Holds the active policy and reloads it on demand (SIGHUP).
 *
 * The critical property is that a bad reload changes nothing. A policy file
 * that fails to parse must leave the previous policy in force: swapping in a
 * partial or empty policy would either deny everything (an outage that looks
 * like a bug) or, worse, silently widen access. Live tunnels and sessions are
 * untouched either way.
 */
export type ReloadResult =
  | { ok: true; apps: string[] }
  | { ok: false; error: string };

export class PolicyStore {
  #policy: Policy;
  #generation = 1;

  private constructor(
    private readonly file: string,
    policy: Policy,
    private readonly read: (f: string) => string,
  ) {
    this.#policy = policy;
  }

  static fromFile(
    file: string,
    read: (f: string) => string = (f) => fs.readFileSync(f, 'utf8'),
  ): PolicyStore {
    // Deliberately not caught: starting with an unparseable policy should fail
    // loudly at boot rather than come up denying everything.
    return new PolicyStore(file, Policy.fromYaml(read(file)), read);
  }

  get(): Policy {
    return this.#policy;
  }

  /** Increments only on a successful reload; useful for logs and tests. */
  get generation(): number {
    return this.#generation;
  }

  reload(): ReloadResult {
    let next: Policy;
    try {
      next = Policy.fromYaml(this.read(this.file));
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }

    this.#policy = next;
    this.#generation += 1;
    return { ok: true, apps: next.apps.map((a) => a.id) };
  }
}
