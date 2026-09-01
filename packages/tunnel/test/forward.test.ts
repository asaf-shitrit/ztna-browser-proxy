import { describe, it, expect, afterEach } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import { once } from 'node:events';
import { forwardDuplex } from '../src/forward.js';

/**
 * Regression coverage for the teardown rule: a tunnel must not outlive the
 * client. Waiting for both sides to close leaks the stream whenever the origin
 * uses keep-alive, and loses the audit record for every successful access.
 *
 * These use real sockets rather than PassThrough pairs on purpose — a
 * PassThrough feeds its own readable side, so piping two together forms an
 * infinite echo loop that a socket pair does not.
 */

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const fn of cleanups.splice(0).reverse()) fn();
});

/** Two ends of a real TCP connection. */
async function socketPair(): Promise<[net.Socket, net.Socket]> {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;

  const a = net.connect(port, '127.0.0.1');
  const [[b]] = (await Promise.all([
    once(server, 'connection'),
    once(a, 'connect'),
  ])) as [[net.Socket], unknown[]];

  server.close();
  cleanups.push(() => {
    a.destroy();
    b.destroy();
  });
  return [a, b];
}

describe('forwardDuplex', () => {
  it('pumps bytes in both directions and counts them', async () => {
    const [client, clientPeer] = await socketPair();
    const [upstream, upstreamPeer] = await socketPair();

    const done = forwardDuplex(client, upstream);

    clientPeer.write('request bytes');
    upstreamPeer.write('response bytes');

    // Let both directions traverse before tearing down.
    await new Promise((r) => setTimeout(r, 100));
    clientPeer.end();
    upstreamPeer.end();

    const result = await withTimeout(done, 5000);
    expect(result.bytesUp).toBe('request bytes'.length);
    expect(result.bytesDown).toBe('response bytes'.length);
  });

  it('resolves when the client vanishes even if the upstream stays open', async () => {
    const [client, clientPeer] = await socketPair();
    const [upstream, upstreamPeer] = await socketPair();

    const done = forwardDuplex(client, upstream);

    // A keep-alive origin: answers, then holds the connection open forever.
    upstreamPeer.write('served');
    await new Promise((r) => setTimeout(r, 50));

    clientPeer.destroy();

    // Must settle promptly rather than hanging on the keep-alive peer. This
    // is the exact case that silently dropped every successful audit record.
    const result = await withTimeout(done, 5000);
    expect(result.bytesDown).toBe('served'.length);
    expect(upstreamPeer.destroyed || upstream.destroyed).toBe(true);
  });

  it('resolves when the upstream vanishes even if the client stays open', async () => {
    const [client] = await socketPair();
    const [upstream, upstreamPeer] = await socketPair();

    const done = forwardDuplex(client, upstream);
    upstreamPeer.destroy();

    await expect(withTimeout(done, 5000)).resolves.toBeDefined();
  });

  it('resolves when a side errors', async () => {
    const [client] = await socketPair();
    const [upstream] = await socketPair();

    const done = forwardDuplex(client, upstream);
    client.destroy(new Error('connection reset'));

    await expect(withTimeout(done, 5000)).resolves.toBeDefined();
  });
});

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`did not settle within ${ms}ms`)), ms),
    ),
  ]);
}
