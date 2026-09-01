import { describe, it, expect, afterEach } from 'vitest';
import tls from 'node:tls';
import net, { type AddressInfo } from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { serveTunnel } from '../src/serve.js';
import { dialTunnel } from '../src/dial.js';
import { writePreamble, readPreamble } from '../src/preamble.js';
import { TUNNEL_ALPN } from '../src/settings.js';

/**
 * The production path, which the plain-TCP tests do not cover: over TLS the
 * auth preamble and the HTTP/2 client preface routinely arrive inside the SAME
 * TLS record. Whatever we read past the preamble must reach the h2 session
 * byte-for-byte, or h2 fails with "Protocol error".
 */

const certDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../infra/certs',
);

const haveCerts = fs.existsSync(path.join(certDir, 'localhost.pem'));

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  for (const fn of cleanups.splice(0).reverse()) await fn();
});

const settle = (ms = 50): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe.skipIf(!haveCerts)('tunnel handshake over TLS', () => {
  it('carries a CONNECT stream when preamble and h2 preface share a record', async () => {
    const origin = net.createServer((s) => s.pipe(s));
    origin.listen(0, '127.0.0.1');
    await once(origin, 'listening');
    const originPort = (origin.address() as AddressInfo).port;
    cleanups.push(() => {
      origin.close();
    });

    // --- POP: accepts TLS, reads the preamble, becomes the h2 CLIENT --------
    let popError: Error | undefined;
    const popReady = Promise.withResolvers<ReturnType<typeof dialTunnel>>();

    const popServer = tls.createServer(
      {
        cert: fs.readFileSync(path.join(certDir, 'localhost.pem')),
        key: fs.readFileSync(path.join(certDir, 'localhost-key.pem')),
        ALPNProtocols: [TUNNEL_ALPN],
      },
      (socket) => {
        void (async () => {
          const preamble = await readPreamble(socket);
          expect(preamble.connectorId).toBe('dc1');
          popReady.resolve(
            dialTunnel(socket, {
              keepAlive: false,
              onError: (err) => {
                popError ??= err;
              },
            }),
          );
        })().catch((err: unknown) => {
          popError ??= err instanceof Error ? err : new Error(String(err));
          popReady.reject(popError);
        });
      },
    );
    popServer.listen(0, '127.0.0.1');
    await once(popServer, 'listening');
    const popPort = (popServer.address() as AddressInfo).port;
    cleanups.push(() => {
      popServer.close();
    });

    // --- Connector: dials TLS, becomes the h2 SERVER ------------------------
    const socket = tls.connect({
      host: '127.0.0.1',
      port: popPort,
      servername: 'localhost',
      ALPNProtocols: [TUNNEL_ALPN],
      ca: [fs.readFileSync(path.join(certDir, 'ca.pem'))],
    });
    await once(socket, 'secureConnect');


    // Must flush before HTTP/2 takes the socket, or Node aborts on the
    // late write completion. This mirrors the real connector exactly.
    await writePreamble(socket, { connectorId: 'dc1', token: 't', version: 1 });

    const tunnel = serveTunnel(socket, {
      control: {
        'GET /catalog': (stream) => {
          stream.respond({ ':status': 200 });
          stream.end(JSON.stringify({ connectorId: 'dc1', apps: [] }));
        },
      },
      onConnect: async (stream, target) => {
        const up = net.connect(target.port, target.host);
        await once(up, 'connect');
        stream.respond({ ':status': 200 });
        stream.pipe(up).pipe(stream);
      },
      onError: () => undefined,
    });
    cleanups.push(async () => {
      tunnel.close();
      await settle();
      socket.destroy();
    });

    const client = await popReady.promise;
    cleanups.push(async () => {
      client.close(); // GOAWAY, not a hard destroy
      await settle();
    });

    // The control request is what failed in production with "Protocol error".
    const catalog = await client.request('GET', '/catalog');
    expect(popError).toBeUndefined();
    expect(catalog.status).toBe(200);
    expect(JSON.parse(catalog.body).connectorId).toBe('dc1');

    // And the data path must work over the same TLS-wrapped session.
    const { stream, status } = await client.openStream('127.0.0.1', originPort);
    expect(status).toBe(200);
    stream.write('tls payload');
    const echoed = await new Promise<Buffer>((resolve) => {
      const chunks: Buffer[] = [];
      let total = 0;
      stream.on('data', (c: Buffer) => {
        chunks.push(c);
        total += c.length;
        if (total >= 11) resolve(Buffer.concat(chunks));
      });
    });
    expect(echoed.toString()).toBe('tls payload');
    stream.close();
    await settle();
  });
});
