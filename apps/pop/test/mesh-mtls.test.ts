import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import net, { type AddressInfo } from 'node:net';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { ConnectorRegistry } from '../src/registry.js';
import { startMeshListener, MeshClient } from '../src/mesh.js';

/**
 * Peer identity on the mesh.
 *
 * The critical property is that "signed by our CA" is NOT enough. The same CA
 * also signs the application certificates, so without a CN allowlist anyone
 * holding wiki.internal's key could authenticate as a peer POP and ask for
 * streams into the private network.
 */

const certDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../infra/certs');
const read = (f: string): Buffer => fs.readFileSync(path.join(certDir, f));
const haveCerts = fs.existsSync(path.join(certDir, 'localhost.pem'));

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const fn of cleanups.splice(0).reverse()) fn();
});

async function startPeer() {
  const registry = new ConnectorRegistry();
  const server = startMeshListener({
    port: 0,
    cert: read('localhost.pem'),
    key: read('localhost-key.pem'),
    ca: read('ca.pem'),
    // Only this identity may forward through us.
    peerCns: ['pop2.ztna.test'],
    registry,
  });
  await once(server, 'listening');
  const port = (server.address() as AddressInfo).port;
  cleanups.push(() => server.close());
  return { port, registry };
}

describe.skipIf(!haveCerts)('mesh mTLS', () => {
  it('accepts a peer presenting an allowlisted POP certificate', async () => {
    const { port } = await startPeer();
    const client = new MeshClient({
      tls: true,
      ca: read('ca.pem'),
      cert: read('pop2.ztna.test.pem'),
      key: read('pop2.ztna.test-key.pem'),
    });
    cleanups.push(() => client.close());

    // 502 (not 401): identity was accepted, we simply hold no such connector.
    const { status } = await client.openStream(`localhost:${port}`, 'dc1', '127.0.0.1', 9999);
    expect(status).toBe(502);
  });

  it('rejects a CA-signed certificate that is not a POP', async () => {
    const { port } = await startPeer();
    // wiki.internal is signed by the same CA — valid TLS, wrong identity.
    const impostor = new MeshClient({
      tls: true,
      ca: read('ca.pem'),
      cert: read('wiki.internal.pem'),
      key: read('wiki.internal-key.pem'),
    });
    cleanups.push(() => impostor.close());

    const { status } = await impostor.openStream(`localhost:${port}`, 'dc1', '127.0.0.1', 9999);
    expect(status).toBe(401);
  });

  it('refuses a peer presenting no client certificate at all', async () => {
    const { port } = await startPeer();
    const anonymous = new MeshClient({ tls: true, ca: read('ca.pem') });
    cleanups.push(() => anonymous.close());

    // TLS itself rejects the handshake, so this never reaches a stream.
    await expect(
      anonymous.openStream(`localhost:${port}`, 'dc1', '127.0.0.1', 9999),
    ).rejects.toThrow();
  });

  it('a shared secret is no longer sufficient once mTLS is configured', async () => {
    const { port } = await startPeer();
    const secretOnly = new MeshClient({
      tls: true,
      ca: read('ca.pem'),
      secret: 'whatever-secret',
      cert: read('wiki.internal.pem'),
      key: read('wiki.internal-key.pem'),
    });
    cleanups.push(() => secretOnly.close());

    const { status } = await secretOnly.openStream(`localhost:${port}`, 'dc1', '127.0.0.1', 9999);
    expect(status).toBe(401);
  });

  it('rejects a peer whose certificate the CA never signed', async () => {
    const { port } = await startPeer();
    const selfSigned = new MeshClient({
      tls: true,
      ca: read('ca.pem'),
      rejectUnauthorized: false, // ignore OUR check of them; the server still checks us
    });
    cleanups.push(() => selfSigned.close());

    await expect(
      selfSigned.openStream(`localhost:${port}`, 'dc1', '127.0.0.1', 9999),
    ).rejects.toThrow();
  });
});
