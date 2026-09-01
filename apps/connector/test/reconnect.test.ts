import { describe, it, expect, afterEach } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import { once } from 'node:events';
import { Policy } from '@ztna/policy';
import { ConnectorRegistry, startTunnelListener, mintToken } from '../../pop/src/registry.js';
import { runConnector, backoffFor, MAX_BACKOFF_MS } from '../src/run.js';
import type { ConnectorConfig } from '../src/config.js';

const SECRET = 'test-connector-secret';

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const fn of cleanups.splice(0).reverse()) fn();
});

const waitFor = async (p: () => boolean, ms = 8000): Promise<void> => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (p()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met');
};

describe('backoffFor', () => {
  it('grows exponentially and then caps', () => {
    const noJitter = 0.5; // multiplier of exactly 1
    expect(backoffFor(0, noJitter)).toBe(1000);
    expect(backoffFor(1, noJitter)).toBe(2000);
    expect(backoffFor(2, noJitter)).toBe(4000);
    expect(backoffFor(20, noJitter)).toBe(MAX_BACKOFF_MS);
  });

  it('spreads retries so a POP restart does not get a thundering herd', () => {
    // Same attempt, different jitter, must not collide on the same tick.
    expect(backoffFor(3, 0)).not.toBe(backoffFor(3, 1));
    expect(backoffFor(3, 0)).toBeGreaterThanOrEqual(4000 * 0.5);
    expect(backoffFor(3, 1)).toBeLessThanOrEqual(8000 * 1.5);
  });
});

describe('connector reconnect', () => {
  it('re-registers with the POP after the POP goes away and comes back', async () => {
    const policy = Policy.fromYaml(`
apps:
  - { id: wiki, hosts: ['127.0.0.1'], ports: [443], connector: dc1 }
rules:
  - { id: r, app: wiki, allow: { groups: [employees] } }
`);
    const registry = new ConnectorRegistry();

    // Plaintext tunnel listener (no cert) on a fixed port so the connector can
    // find it again after a restart — exactly what a POP restart looks like.
    const startPop = async (port: number) => {
      const server = startTunnelListener({
        port,
        connectorSecret: SECRET,
        registry,
        validateCatalog: (c) =>
          c.apps.every((a) => policy.apps.some((p) => p.id === a.id)) ? null : 'unknown app',
      });
      await once(server, 'listening');
      return server;
    };

    // Grab a free port, then reuse it for both POP incarnations.
    const probe = net.createServer();
    probe.listen(0, '127.0.0.1');
    await once(probe, 'listening');
    const port = (probe.address() as AddressInfo).port;
    probe.close();
    await once(probe, 'close');

    let pop = await startPop(port);
    cleanups.push(() => pop.close());

    const config: ConnectorConfig = {
      connectorId: 'dc1',
      popHost: '127.0.0.1',
      popPort: port,
      token: mintToken('dc1', SECRET),
      apps: [{ id: 'wiki', hosts: ['127.0.0.1'], ports: [443] }],
      insecureSkipVerify: true,
      connectTimeoutMs: 2000,
      idleTimeoutMs: 30_000,
    };

    let stop = false;
    const loop = runConnector(config, {
      connect: async (c) => {
        const s = net.connect(c.popPort, c.popHost);
        await once(s, 'connect');
        cleanups.push(() => s.destroy());
        return s;
      },
      sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 150))),
      shouldStop: () => stop,
      jitter: () => 0.5,
    });
    cleanups.push(() => {
      stop = true;
    });

    await waitFor(() => registry.get('dc1') !== undefined);
    expect(registry.get('dc1')?.catalog.apps.map((a) => a.id)).toEqual(['wiki']);

    // The POP dies. The connector must notice and stop being registered.
    pop.close();
    for (const c of registry.list()) c.client.destroy();
    await waitFor(() => registry.get('dc1') === undefined);

    // The POP comes back on the same address; the connector must return on its
    // own, with no operator action and no re-issued token.
    pop = await startPop(port);
    cleanups.push(() => pop.close());

    await waitFor(() => registry.get('dc1') !== undefined, 15000);
    expect(registry.get('dc1')?.catalog.apps.map((a) => a.id)).toEqual(['wiki']);

    stop = true;
    await Promise.race([loop, new Promise((r) => setTimeout(r, 500))]);
  }, 30_000);
});
