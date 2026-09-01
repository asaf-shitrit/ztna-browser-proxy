import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import http from 'node:http';
import { once } from 'node:events';
import { Policy, type Identity } from '@ztna/policy';
import { serveTunnel, encodePreamble, writePreamble } from '@ztna/tunnel';
import { ConnectorRegistry, startTunnelListener, mintToken } from '../src/registry.js';
import { startProxy } from '../src/proxy.js';
import { startMeshListener, MeshClient } from '../src/mesh.js';
import { MemorySessionStore } from '../src/sessions.js';
import { AuditLog } from '../src/audit.js';
import type { OwnershipRegistry } from '../src/ownership.js';
import { createHandlers } from '../../connector/src/handlers.js';
import type { ConnectorConfig } from '../../connector/src/config.js';

/**
 * Two POPs. The connector attaches to POP A; the client attaches to POP B.
 * B must discover that A owns the connector and forward the stream, which is
 * what makes "everyone connects to the closest POP" workable.
 */

const SECRET = 'test-connector-secret';
const MESH_SECRET = 'test-mesh-secret';
const alice: Identity = { sub: 'u-alice', email: 'a@x', groups: ['employees'] };

/** Shared ownership map standing in for Redis, with call counting. */
class FakeOwnership implements OwnershipRegistry {
  static readonly map = new Map<string, string>();
  static lookups = 0;

  constructor(private readonly self: string) {}

  async claim(id: string): Promise<void> {
    FakeOwnership.map.set(id, this.self);
  }
  async release(id: string): Promise<void> {
    if (FakeOwnership.map.get(id) === this.self) FakeOwnership.map.delete(id);
  }
  async lookup(id: string): Promise<string | null> {
    FakeOwnership.lookups += 1;
    return FakeOwnership.map.get(id) ?? null;
  }
  close(): void {}
}

let originPort = 0;
let proxyAPort = 0;
let proxyBPort = 0;
let policy: Policy;

const sessionsA = new MemorySessionStore();
const sessionsB = new MemorySessionStore();
const auditA = new AuditLog();
const auditB = new AuditLog();
const registryA = new ConnectorRegistry();
const registryB = new ConnectorRegistry();
const teardown: Array<() => void> = [];

const waitFor = async (p: () => boolean, ms = 8000): Promise<void> => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (p()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met');
};

beforeAll(async () => {
  const origin = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('served from the private network');
  });
  origin.listen(0, '127.0.0.1');
  await once(origin, 'listening');
  originPort = (origin.address() as AddressInfo).port;
  teardown.push(() => origin.close());

  policy = Policy.fromYaml(`
apps:
  - { id: wiki, hosts: ['127.0.0.1'], ports: [${originPort}], connector: dc1 }
rules:
  - { id: employees-wiki, app: wiki, allow: { groups: [employees] } }
`);

  // --- POP A: holds the connector -----------------------------------------
  const meshA = startMeshListener({
    port: 0,
    secret: MESH_SECRET,
    registry: registryA,
  });
  await once(meshA, 'listening');
  const meshAPort = (meshA.address() as AddressInfo).port;
  const meshAAddress = `127.0.0.1:${meshAPort}`;
  teardown.push(() => meshA.close());

  const ownershipA = new FakeOwnership(meshAAddress);

  const tunnelA = startTunnelListener({
    port: 0,
    connectorSecret: SECRET,
    registry: registryA,
    ownership: ownershipA,
  });
  await once(tunnelA, 'listening');
  const tunnelAPort = (tunnelA.address() as AddressInfo).port;
  teardown.push(() => tunnelA.close());

  const proxyA = startProxy({
    port: 0,
    policy: () => policy,
    registry: registryA,
    sessions: sessionsA,
    audit: auditA,
    ownership: ownershipA,
    mesh: new MeshClient({ secret: MESH_SECRET, tls: false }),
    meshAddress: meshAAddress,
  });
  await once(proxyA, 'listening');
  proxyAPort = (proxyA.address() as AddressInfo).port;
  teardown.push(() => proxyA.close());

  // --- POP B: holds nothing ------------------------------------------------
  const ownershipB = new FakeOwnership('127.0.0.1:59999');
  const meshClientB = new MeshClient({ secret: MESH_SECRET, tls: false });
  teardown.push(() => meshClientB.close());

  const proxyB = startProxy({
    port: 0,
    policy: () => policy,
    registry: registryB,
    sessions: sessionsB,
    audit: auditB,
    ownership: ownershipB,
    mesh: meshClientB,
    meshAddress: '127.0.0.1:59999',
  });
  await once(proxyB, 'listening');
  proxyBPort = (proxyB.address() as AddressInfo).port;
  teardown.push(() => proxyB.close());

  // --- the connector attaches to POP A only --------------------------------
  const config: ConnectorConfig = {
    connectorId: 'dc1',
    popHost: '127.0.0.1',
    popPort: tunnelAPort,
    token: mintToken('dc1', SECRET),
    apps: [{ id: 'wiki', hosts: ['127.0.0.1'], ports: [originPort] }],
    insecureSkipVerify: true,
    connectTimeoutMs: 3000,
    idleTimeoutMs: 30_000,
  };

  const socket = net.connect(tunnelAPort, '127.0.0.1');
  await once(socket, 'connect');
  await writePreamble(socket, { connectorId: 'dc1', token: config.token, version: 1 });
  const tunnel = serveTunnel(socket, createHandlers(config));
  teardown.push(() => {
    tunnel.close();
    socket.destroy();
  });

  await waitFor(() => registryA.get('dc1') !== undefined);
});

afterAll(() => {
  for (const fn of teardown.reverse()) fn();
});

function proxyGet(port: number, url: string, creds: { proxyUser: string; proxySecret: string }) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const basic = Buffer.from(`${creds.proxyUser}:${creds.proxySecret}`).toString('base64');
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method: 'GET',
        path: url,
        headers: { host: new URL(url).host, 'proxy-authorization': `Basic ${basic}` },
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

describe('multi-POP routing', () => {
  it('publishes ownership when a connector attaches', () => {
    expect(FakeOwnership.map.get('dc1')).toMatch(/^127\.0\.0\.1:\d+$/);
  });

  it('serves locally without consulting ownership at all', async () => {
    const session = await sessionsA.create(alice, 60_000);
    const before = FakeOwnership.lookups;

    const res = await proxyGet(proxyAPort, `http://127.0.0.1:${originPort}/`, session);
    expect(res.status).toBe(200);
    expect(res.body).toContain('served from the private network');

    // The whole point of local-first: the common case pays no lookup.
    expect(FakeOwnership.lookups).toBe(before);
  });

  it('forwards to the owning POP when the connector is elsewhere', async () => {
    const session = await sessionsB.create(alice, 60_000);
    const before = FakeOwnership.lookups;

    // POP B holds no connector, yet the client still reaches the private app.
    expect(registryB.get('dc1')).toBeUndefined();

    const res = await proxyGet(proxyBPort, `http://127.0.0.1:${originPort}/`, session);
    expect(res.status).toBe(200);
    expect(res.body).toContain('served from the private network');

    // This path does consult ownership.
    expect(FakeOwnership.lookups).toBeGreaterThan(before);
  });

  it('still enforces policy on the forwarding POP', async () => {
    const bob = { sub: 'u-bob', groups: ['finance'] };
    const session = await sessionsB.create(bob, 60_000);

    // Authorization happens before any forwarding decision.
    const res = await proxyGet(proxyBPort, `http://127.0.0.1:${originPort}/`, session);
    expect(res.status).toBe(403);
  });

  it('rejects a peer that does not present the mesh secret', async () => {
    const impostor = new MeshClient({ secret: 'wrong-secret', tls: false });
    const owner = FakeOwnership.map.get('dc1')!;

    const { status } = await impostor.openStream(owner, 'dc1', '127.0.0.1', originPort);
    expect(status).toBe(401);
    impostor.close();
  });

  it('refuses to forward onward for a connector it does not hold', async () => {
    // A peer must serve only from its local registry, or two POPs each
    // believing the other owns a connector would bounce the stream forever.
    const client = new MeshClient({ secret: MESH_SECRET, tls: false });
    const owner = FakeOwnership.map.get('dc1')!;

    const { status } = await client.openStream(owner, 'unknown-connector', '127.0.0.1', originPort);
    expect(status).toBe(502);
    client.close();
  });

  it('502s rather than looping when the lease points at this POP but is stale', async () => {
    // Simulate a dropped connector whose lease has not expired yet.
    FakeOwnership.map.set('ghost', '127.0.0.1:59999');
    const ghostPolicy = Policy.fromYaml(`
apps:
  - { id: ghost, hosts: ['127.0.0.1'], ports: [${originPort}], connector: ghost }
rules:
  - { id: r, app: ghost, allow: { groups: [employees] } }
`);
    policy = ghostPolicy;

    const session = await sessionsB.create(alice, 60_000);
    const res = await proxyGet(proxyBPort, `http://127.0.0.1:${originPort}/`, session);
    expect(res.status).toBe(502);
  });
});
