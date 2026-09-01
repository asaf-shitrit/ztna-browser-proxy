import { describe, it, expect, afterEach } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import { once } from 'node:events';
import { serveTunnel, parseAuthority } from '../src/serve.js';
import { dialTunnel, TunnelClient } from '../src/dial.js';
import { forwardDuplex } from '../src/forward.js';
import { encodePreamble, readPreamble } from '../src/preamble.js';

/**
 * These tests exercise the role inversion end to end over a real socket pair:
 * the "connector" dials, then becomes the h2 server; the "POP" accepts, then
 * becomes the h2 client and opens streams.
 */

interface Harness {
  client: TunnelClient;
  close: () => Promise<void>;
}

const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const fn of cleanups.splice(0).reverse()) {
    await fn();
  }
});

/** Spin up a connector-side tunnel and a POP-side client joined by TCP. */
async function makeTunnel(opts: {
  onConnect: Parameters<typeof serveTunnel>[1]['onConnect'];
  control?: Parameters<typeof serveTunnel>[1]['control'];
  withPreamble?: boolean;
}): Promise<Harness> {
  const popSockets: net.Socket[] = [];
  let resolveClient!: (c: TunnelClient) => void;
  const clientReady = new Promise<TunnelClient>((r) => {
    resolveClient = r;
  });

  // The POP: TCP listener that becomes the h2 CLIENT.
  const popServer = net.createServer((socket) => {
    popSockets.push(socket);
    void (async () => {
      if (opts.withPreamble) {
        const preamble = await readPreamble(socket);
        expect(preamble.connectorId).toBe('dc1');
      }
      resolveClient(dialTunnel(socket, { keepAlive: false }));
    })();
  });

  popServer.listen(0, '127.0.0.1');
  await once(popServer, 'listening');
  const { port } = popServer.address() as AddressInfo;

  // The connector: TCP dialer that becomes the h2 SERVER.
  const connectorSocket = net.connect(port, '127.0.0.1');
  await once(connectorSocket, 'connect');

  if (opts.withPreamble) {
    connectorSocket.write(
      encodePreamble({ connectorId: 'dc1', token: 'secret', version: 1 }),
    );
  }

  const tunnelServer = serveTunnel(connectorSocket, {
    control: opts.control ?? {},
    onConnect: opts.onConnect,
    onError: () => {
      /* connection teardown races are expected in tests */
    },
  });

  const client = await clientReady;

  const close = async (): Promise<void> => {
    client.destroy();
    tunnelServer.close();
    connectorSocket.destroy();
    for (const s of popSockets) s.destroy();
    popServer.close();
    await once(popServer, 'close').catch(() => undefined);
  };
  cleanups.push(close);

  return { client, close };
}

describe('parseAuthority', () => {
  it('parses host:port', () => {
    expect(parseAuthority('wiki.internal:443')).toEqual({
      host: 'wiki.internal',
      port: 443,
    });
  });

  it('parses bracketed IPv6', () => {
    expect(parseAuthority('[::1]:8080')).toEqual({ host: '::1', port: 8080 });
  });

  it('rejects malformed input', () => {
    expect(parseAuthority(undefined)).toBeNull();
    expect(parseAuthority('wiki.internal')).toBeNull();
    expect(parseAuthority('wiki.internal:0')).toBeNull();
    expect(parseAuthority('wiki.internal:99999')).toBeNull();
    expect(parseAuthority(':443')).toBeNull();
    // Unbracketed IPv6 is ambiguous and must not be guessed at.
    expect(parseAuthority('::1:443')).toBeNull();
  });
});

describe('preamble framing', () => {
  it('reads exactly the preamble and leaves the rest for HTTP/2', async () => {
    const [a, b] = await makeSocketPair();

    const trailing = Buffer.from('PRI * HTTP/2.0\r\n');
    a.write(Buffer.concat([
      encodePreamble({ connectorId: 'dc1', token: 't', version: 1 }),
      trailing,
    ]));

    const preamble = await readPreamble(b);
    expect(preamble).toEqual({ connectorId: 'dc1', token: 't', version: 1 });

    // Critical: the h2 preface must survive untouched.
    const rest = await readAll(b, trailing.length);
    expect(rest.toString()).toBe(trailing.toString());

    a.destroy();
    b.destroy();
  });

  it('rejects a preamble that fails schema validation', async () => {
    const [a, b] = await makeSocketPair();
    const body = Buffer.from(JSON.stringify({ connectorId: 'dc1' }));
    const header = Buffer.allocUnsafe(4);
    header.writeUInt32BE(body.length, 0);
    a.write(Buffer.concat([header, body]));

    await expect(readPreamble(b)).rejects.toThrow();
    a.destroy();
    b.destroy();
  });
});

describe('tunnel role inversion', () => {
  it('lets the POP open a CONNECT stream through a connector that dialled out', async () => {
    const origin = await makeEchoServer();

    const { client } = await makeTunnel({
      withPreamble: true,
      onConnect: async (stream, target) => {
        const socket = net.connect(target.port, target.host);
        await once(socket, 'connect');
        stream.respond({ ':status': 200 });
        await forwardDuplex(stream, socket);
      },
    });

    const { stream, status } = await client.openStream('127.0.0.1', origin.port);
    expect(status).toBe(200);

    stream.write('hello tunnel');
    const echoed = await readAll(stream, 'hello tunnel'.length);
    expect(echoed.toString()).toBe('hello tunnel');

    stream.close();
    await origin.close();
  });

  it('serves control requests over the same session', async () => {
    const { client } = await makeTunnel({
      onConnect: (stream) => {
        stream.respond({ ':status': 502 });
        stream.end();
      },
      control: {
        'GET /catalog': (stream) => {
          stream.respond({ ':status': 200, 'content-type': 'application/json' });
          stream.end(JSON.stringify({ connectorId: 'dc1', apps: [] }));
        },
      },
    });

    const res = await client.request('GET', '/catalog');
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ connectorId: 'dc1', apps: [] });
  });

  it('returns 404 for an unknown control route', async () => {
    const { client } = await makeTunnel({
      onConnect: (stream) => {
        stream.respond({ ':status': 200 });
        stream.end();
      },
    });

    const res = await client.request('GET', '/nope');
    expect(res.status).toBe(404);
  });

  it('surfaces the connector refusing a target as a non-200 status', async () => {
    const { client } = await makeTunnel({
      onConnect: (stream) => {
        stream.respond({ ':status': 502 });
        stream.end();
      },
    });

    const { status } = await client.openStream('blocked.internal', 443);
    expect(status).toBe(502);
  });

  it('multiplexes concurrent streams over the single connection', async () => {
    const origin = await makeEchoServer();

    const { client } = await makeTunnel({
      onConnect: async (stream, target) => {
        const socket = net.connect(target.port, target.host);
        await once(socket, 'connect');
        stream.respond({ ':status': 200 });
        await forwardDuplex(stream, socket);
      },
    });

    const results = await Promise.all(
      Array.from({ length: 20 }, async (_, i) => {
        const { stream, status } = await client.openStream('127.0.0.1', origin.port);
        expect(status).toBe(200);
        const payload = `stream-${i}`;
        stream.write(payload);
        const out = await readAll(stream, payload.length);
        stream.close();
        return out.toString();
      }),
    );

    expect(results).toEqual(Array.from({ length: 20 }, (_, i) => `stream-${i}`));
    await origin.close();
  });

  it('rejects opening a stream once the session is closed', async () => {
    const { client } = await makeTunnel({
      onConnect: (stream) => {
        stream.respond({ ':status': 200 });
        stream.end();
      },
    });

    client.destroy();
    await expect(client.openStream('wiki.internal', 443)).rejects.toThrow(/closed/);
  });
});

// ---------------------------------------------------------------- helpers

/** A connected pair of sockets over loopback. */
async function makeSocketPair(): Promise<[net.Socket, net.Socket]> {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;

  const a = net.connect(port, '127.0.0.1');
  // Attach both listeners before awaiting: 'connect' fires on the client at
  // roughly the same tick as 'connection' on the server, so awaiting them in
  // sequence can miss the first one and hang forever.
  const [[b]] = (await Promise.all([
    once(server, 'connection'),
    once(a, 'connect'),
  ])) as [[net.Socket], unknown[]];
  server.close();

  return [a, b];
}

async function makeEchoServer(): Promise<{ port: number; close: () => Promise<void> }> {
  const server = net.createServer((socket) => socket.pipe(socket));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  return {
    port,
    close: async () => {
      server.close();
      await once(server, 'close').catch(() => undefined);
    },
  };
}

/** Read until `n` bytes have accumulated. */
function readAll(stream: NodeJS.ReadableStream, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= n) {
        stream.removeListener('data', onData);
        stream.removeListener('error', reject);
        resolve(Buffer.concat(chunks));
      }
    };
    stream.on('data', onData);
    stream.on('error', reject);
  });
}

describe('flow control and shutdown', () => {
  it('stalls a fast producer when the consumer never reads', async () => {
    const TARGET = 128 * 1024 * 1024; // far more than any window allows
    let written = 0;

    // An origin that blasts data as fast as TCP will accept it.
    const origin = net.createServer((socket) => {
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      const pump = (): void => {
        while (written < TARGET) {
          written += chunk.length;
          if (!socket.write(chunk)) {
            socket.once('drain', pump);
            return;
          }
        }
      };
      pump();
    });
    origin.listen(0, '127.0.0.1');
    await once(origin, 'listening');
    const originPort = (origin.address() as AddressInfo).port;

    const { client } = await makeTunnel({
      onConnect: async (stream, target) => {
        const socket = net.connect(target.port, target.host);
        await once(socket, 'connect');
        stream.respond({ ':status': 200 });
        await forwardDuplex(stream, socket);
      },
    });

    const { stream, status } = await client.openStream('127.0.0.1', originPort);
    expect(status).toBe(200);

    // Deliberately never read from `stream`. If flow control works, the
    // producer stalls once the window and socket buffers fill. If it is
    // broken, the origin runs to completion and the bytes pile up in the
    // POP's heap — exactly the failure this test exists to catch.
    await new Promise((r) => setTimeout(r, 500));

    if (process.env.DEBUG_FLOW) console.log("stalled at bytes:", written);
    expect(written).toBeLessThan(32 * 1024 * 1024);
    expect(written).toBeGreaterThan(0);

    stream.close();
    origin.close();
    await once(origin, 'close').catch(() => undefined);
  });

  it('lets in-flight streams finish after GOAWAY but refuses new ones', async () => {
    const origin = await makeEchoServer();

    const { client } = await makeTunnel({
      onConnect: async (stream, target) => {
        const socket = net.connect(target.port, target.host);
        await once(socket, 'connect');
        stream.respond({ ':status': 200 });
        await forwardDuplex(stream, socket);
      },
    });

    const { stream } = await client.openStream('127.0.0.1', origin.port);
    stream.write('before');
    expect((await readAll(stream, 6)).toString()).toBe('before');

    client.close(); // sends GOAWAY

    // The existing stream must survive a graceful drain.
    stream.write('after');
    expect((await readAll(stream, 5)).toString()).toBe('after');

    // But the session must not accept new work.
    await expect(client.openStream('127.0.0.1', origin.port)).rejects.toThrow(/closed/);

    stream.close();
    await origin.close();
  });
});
