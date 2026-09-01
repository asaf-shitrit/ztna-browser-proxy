import { describe, it, expect } from 'vitest';
import { Policy, matchesHost, type Identity } from '../src/index.js';

const YAML = `
apps:
  - id: wiki
    hosts: [wiki.internal]
    ports: [80, 443]
    connector: dc1
  - id: payroll
    hosts: [payroll.internal]
    ports: [443]
    connector: dc1
  - id: tools
    hosts: ["*.tools.internal"]
    ports: [443]
    connector: dc2
rules:
  - id: employees-wiki
    app: wiki
    allow: { groups: [employees] }
  - id: finance-payroll
    app: payroll
    allow: { groups: [finance] }
  - id: named-user-tools
    app: tools
    allow: { users: ["alice@example.com"] }
`;

const policy = Policy.fromYaml(YAML);

const alice: Identity = { sub: 'u-alice', email: 'alice@example.com', groups: ['employees'] };
const bob: Identity = { sub: 'u-bob', email: 'bob@example.com', groups: ['finance'] };
const nobody: Identity = { sub: 'u-nobody', email: 'nobody@example.com', groups: [] };

describe('Policy.evaluate', () => {
  it('allows an identity whose group matches a rule', () => {
    const d = policy.evaluate({ identity: alice, host: 'wiki.internal', port: 443 });
    expect(d).toMatchObject({
      effect: 'allow',
      appId: 'wiki',
      ruleId: 'employees-wiki',
      connectorId: 'dc1',
    });
  });

  it('denies an identity in the wrong group', () => {
    const d = policy.evaluate({ identity: bob, host: 'wiki.internal', port: 443 });
    expect(d).toMatchObject({ effect: 'deny', reason: 'no-matching-rule', appId: 'wiki' });
  });

  it('denies by default when no rule grants access', () => {
    const d = policy.evaluate({ identity: nobody, host: 'wiki.internal', port: 443 });
    expect(d.effect).toBe('deny');
  });

  it('denies an unknown host', () => {
    const d = policy.evaluate({ identity: alice, host: 'secret.internal', port: 443 });
    expect(d).toMatchObject({ effect: 'deny', reason: 'no-matching-app' });
  });

  it('denies a known host on a port the app does not declare', () => {
    const d = policy.evaluate({ identity: bob, host: 'payroll.internal', port: 8080 });
    expect(d).toMatchObject({ effect: 'deny', reason: 'no-matching-app' });
  });

  it('is case-insensitive on hostnames', () => {
    const d = policy.evaluate({ identity: alice, host: 'WIKI.Internal', port: 443 });
    expect(d.effect).toBe('allow');
  });

  it('matches a user by email as well as by subject', () => {
    const d = policy.evaluate({ identity: alice, host: 'ci.tools.internal', port: 443 });
    expect(d).toMatchObject({ effect: 'allow', appId: 'tools', connectorId: 'dc2' });
  });

  it('does not leak one app grant into another', () => {
    // alice is allowed wiki + tools, but never payroll.
    expect(policy.evaluate({ identity: alice, host: 'payroll.internal', port: 443 }).effect)
      .toBe('deny');
    expect(policy.evaluate({ identity: bob, host: 'payroll.internal', port: 443 }).effect)
      .toBe('allow');
  });

  it('reports the connector so the POP can route the stream', () => {
    const d = policy.evaluate({ identity: bob, host: 'payroll.internal', port: 443 });
    expect(d.connectorId).toBe('dc1');
  });
});

describe('Policy.appsFor', () => {
  it('returns only the apps the identity can reach', () => {
    expect(policy.appsFor(alice).map((a) => a.id).sort()).toEqual(['tools', 'wiki']);
    expect(policy.appsFor(bob).map((a) => a.id)).toEqual(['payroll']);
    expect(policy.appsFor(nobody)).toEqual([]);
  });
});

describe('matchesHost', () => {
  it('matches exact hostnames only', () => {
    expect(matchesHost('wiki.internal', 'wiki.internal')).toBe(true);
    expect(matchesHost('wiki.internal', 'evil-wiki.internal')).toBe(false);
    expect(matchesHost('wiki.internal', 'wiki.internal.evil.com')).toBe(false);
  });

  it('matches exactly one label for a wildcard', () => {
    expect(matchesHost('*.internal', 'wiki.internal')).toBe(true);
    expect(matchesHost('*.internal', 'a.b.internal')).toBe(false);
    expect(matchesHost('*.internal', 'internal')).toBe(false);
    expect(matchesHost('*.internal', '.internal')).toBe(false);
  });

  it('does not let a wildcard match a lookalike suffix', () => {
    expect(matchesHost('*.internal', 'wiki.notinternal')).toBe(false);
    expect(matchesHost('*.internal', 'wiki.internal.attacker.com')).toBe(false);
  });
});

describe('policy document validation', () => {
  it('rejects a rule referencing an unknown app', () => {
    expect(() =>
      Policy.fromYaml(`
apps: [{ id: a, hosts: [a.internal], ports: [443], connector: dc1 }]
rules: [{ app: ghost, allow: { groups: [x] } }]
`),
    ).toThrow(/unknown app/);
  });

  it('rejects duplicate app ids', () => {
    expect(() =>
      Policy.fromYaml(`
apps:
  - { id: a, hosts: [a.internal], ports: [443], connector: dc1 }
  - { id: a, hosts: [b.internal], ports: [443], connector: dc1 }
rules: []
`),
    ).toThrow(/duplicate app id/);
  });

  it('rejects an empty allow block that would grant everyone access', () => {
    expect(() =>
      Policy.fromYaml(`
apps: [{ id: a, hosts: [a.internal], ports: [443], connector: dc1 }]
rules: [{ app: a, allow: {} }]
`),
    ).toThrow(/at least one group or user/);
  });

  it('rejects a greedy wildcard pattern', () => {
    expect(() =>
      Policy.fromYaml(`
apps: [{ id: a, hosts: ["*"], ports: [443], connector: dc1 }]
rules: []
`),
    ).toThrow(/wildcards must be/);
  });

  it('rejects an out-of-range port', () => {
    expect(() =>
      Policy.fromYaml(`
apps: [{ id: a, hosts: [a.internal], ports: [70000], connector: dc1 }]
rules: []
`),
    ).toThrow();
  });
});
