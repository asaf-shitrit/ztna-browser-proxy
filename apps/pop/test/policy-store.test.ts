import { describe, it, expect } from 'vitest';
import { PolicyStore } from '../src/policy-store.js';

const GOOD = `
apps:
  - { id: wiki, hosts: [wiki.internal], ports: [443], connector: dc1 }
rules:
  - { id: employees-wiki, app: wiki, allow: { groups: [employees] } }
`;

const WIDER = `
apps:
  - { id: wiki, hosts: [wiki.internal], ports: [443], connector: dc1 }
  - { id: payroll, hosts: [payroll.internal], ports: [443], connector: dc1 }
rules:
  - { id: employees-wiki, app: wiki, allow: { groups: [employees] } }
  - { id: finance-payroll, app: payroll, allow: { groups: [finance] } }
`;

const BROKEN = 'apps: [ this is not: valid policy ]';

const alice = { sub: 'u-alice', groups: ['employees'] };

/** A fake file whose contents the test controls between reloads. */
function fakeFile(initial: string) {
  let content = initial;
  return {
    read: () => content,
    set: (next: string) => {
      content = next;
    },
  };
}

describe('PolicyStore', () => {
  it('fails loudly at boot on an unparseable policy', () => {
    // Coming up with an empty policy would deny everything and look like an
    // outage rather than a config error.
    expect(() => PolicyStore.fromFile('x', () => BROKEN)).toThrow();
  });

  it('serves the loaded policy', () => {
    const store = PolicyStore.fromFile('x', fakeFile(GOOD).read);
    expect(store.get().evaluate({ identity: alice, host: 'wiki.internal', port: 443 }).effect)
      .toBe('allow');
  });

  it('picks up a valid change on reload', () => {
    const file = fakeFile(GOOD);
    const store = PolicyStore.fromFile('x', file.read);

    expect(store.get().apps.map((a) => a.id)).toEqual(['wiki']);

    file.set(WIDER);
    const result = store.reload();

    expect(result).toEqual({ ok: true, apps: ['wiki', 'payroll'] });
    expect(store.get().apps.map((a) => a.id)).toEqual(['wiki', 'payroll']);
    expect(store.generation).toBe(2);
  });

  it('keeps the previous policy when a reload fails', () => {
    const file = fakeFile(GOOD);
    const store = PolicyStore.fromFile('x', file.read);

    file.set(BROKEN);
    const result = store.reload();

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeTruthy();

    // The whole point: a bad edit must not change enforcement.
    expect(store.generation).toBe(1);
    expect(store.get().evaluate({ identity: alice, host: 'wiki.internal', port: 443 }).effect)
      .toBe('allow');
  });

  it('refuses to start when the policy file is missing', () => {
    expect(() =>
      PolicyStore.fromFile('x', () => {
        throw new Error('ENOENT: no such file');
      }),
    ).toThrow(/ENOENT/);
  });

  it('survives a transient read error and recovers on the next reload', () => {
    let mode: 'good' | 'throw' | 'wider' = 'good';
    const store = PolicyStore.fromFile('x', () => {
      if (mode === 'throw') throw new Error('ENOENT: no such file');
      return mode === 'wider' ? WIDER : GOOD;
    });

    mode = 'throw';
    expect(store.reload().ok).toBe(false);
    expect(store.get().apps.map((a) => a.id)).toEqual(['wiki']);

    mode = 'wider';
    expect(store.reload().ok).toBe(true);
    expect(store.get().apps.map((a) => a.id)).toEqual(['wiki', 'payroll']);
  });
});
