import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import http from 'node:http';
import { once } from 'node:events';
import { Policy, type Identity } from '@ztna/policy';
import { serveTunnel, encodePreamble, type Catalog } from '@ztna/tunnel';
import { ConnectorRegistry, startTunnelListener, mintToken } from '../src/registry.js';
import { startProxy } from '../src/proxy.js';
import { MemorySessionStore } from '../src/sessions.js';
import { AuditLog } from '../src/audit.js';
import { RateLimiter } from '../src/rate-limit.js';
import { createHandlers } from '../../connector/src/handlers.js';
import type { ConnectorConfig } from '../../connector/src/config.js';

/**
 * End-to-end through the real POP and the real connector handlers: browser
 * CONNECT -> proxy auth -> policy -> tunnel -> private origin.
 */

const CONNECTOR_SECRET = 'test-connector-secret';

const alice: Identity = { sub: 'u-alice', email: 'alice@example.com', groups: ['employees'] };
const bob: Identity = { sub: 'u-bob', email: 'bob@example.com', groups: ['finance'] };

let wikiPort = 0;
let payrollPort = 0;
let httpAppPort = 0;
let proxyPort = 0;
let policy: Policy;

const registry = new ConnectorRegistry();
const sessions = new MemorySessionStore();
const audit = new AuditLog();
// Small limit so the brute-force test does not need 20 round trips.
const authLimiter = new RateLimiter({ limit: 3, windowMs: 60_000 });
const teardown: Array<() => void> = [];

let connectorSocket: net.Socket;

beforeAll(async () => {
  // Two private origins standing in for wiki.internal and payroll.internal.
  const wiki = await echoServer();
  const payroll = await echoServer();
  wikiPort = wiki.port;
  payrollPort = payroll.port;
  teardown.push(wiki.close, payroll.close);

  // A real HTTP origin for the absolute-form path (no CONNECT involved).
  const httpApp = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => {
      body += String(c);
    });
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`method=${req.method} url=${req.url} host=${req.headers.host} body=${body}`);
    });
  });
  httpApp.listen(0, '127.0.0.1');
  await once(httpApp, 'listening');
  httpAppPort = (httpApp.address() as AddressInfo).port;
  teardown.push(() => httpApp.close());

  // Ports are ephemeral, so the policy is built around them.
  policy = Policy.fromYaml(`
apps:
  - id: wiki
    hosts: ['127.0.0.1']
    ports: [${wikiPort}]
    connector: dc1
  - id: payroll
    hosts: ['127.0.0.1']
    ports: [${payrollPort}]
    connector: dc1
  - id: plain
    hosts: ['127.0.0.1']
    ports: [${httpAppPort}]
    connector: dc1
rules:
  - id: employees-wiki
    app: wiki
    allow: { groups: [employees] }
  - id: finance-payroll
    app: payroll
    allow: { groups: [finance] }
  - id: employees-plain
    app: plain
    allow: { groups: [employees] }
`);

  const tunnelListener = startTunnelListener({
    port: 0,
    connectorSecret: CONNECTOR_SECRET,
    registry,
    validateCatalog: (catalog: Catalog) => {
      for (const app of catalog.apps) {
        const declared = policy.apps.find((a) => a.id === app.id);
        if (!declared) return `unknown app ${app.id}`;
        if (declared.connector !== catalog.connectorId) return `wrong connector for ${app.id}`;
      }
      return null;
    },
  });
  await once(tunnelListener, 'listening');
  const tunnelPort = (tunnelListener.address() as AddressInfo).port;
  teardown.push(() => tunnelListener.close());

  // The connector: dials out, then serves HTTP/2 on the socket it dialled.
  const connectorConfig: ConnectorConfig = {
    connectorId: 'dc1',
    popHost: '127.0.0.1',
    popPort: tunnelPort,
    token: mintToken('dc1', CONNECTOR_SECRET),
    apps: [
      { id: 'wiki', hosts: ['127.0.0.1'], ports: [wikiPort] },
      { id: 'payroll', hosts: ['127.0.0.1'], ports: [payrollPort] },
      { id: 'plain', hosts: ['127.0.0.1'], ports: [httpAppPort] },
    ],
    insecureSkipVerify: true,
    connectTimeoutMs: 5000,
    idleTimeoutMs: 60_000,
  };

  connectorSocket = net.connect(tunnelPort, '127.0.0.1');
  await once(connectorSocket, 'connect');
  connectorSocket.write(
    encodePreamble({ connectorId: 'dc1', token: connectorConfig.token, version: 1 }),
  );
  const tunnel = serveTunnel(connectorSocket, createHandlers(connectorConfig));
  teardown.push(() => tunnel.close());

  await waitFor(() => registry.get('dc1') !== undefined);

  const proxy = startProxy({
    port: 0,
    policy: () => policy,
    registry,
    sessions,
    audit,
    authLimiter,
  });
  await once(proxy, 'listening');
  proxyPort = (proxy.address() as AddressInfo).port;
  teardown.push(() => proxy.close());
});

afterAll(() => {
  connectorSocket?.destroy();
  for (const fn of teardown.reverse()) fn();
});

describe('POP proxy end to end', () => {
  it('registers the connector and its catalog', () => {
    const entry = registry.get('dc1');
    expect(entry?.catalog.apps.map((a) => a.id).sort()).toEqual(['payroll', 'plain', 'wiki']);
  });

  it('proxies bytes to a private origin for an authorized user', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);

    expect(res.status).toBe(200);
    res.socket!.write('through the tunnel');
    const echoed = await readN(res.socket!, 'through the tunnel'.length);
    expect(echoed.toString()).toBe('through the tunnel');
    res.socket!.destroy();
  });

  it('counts bytes in both directions for the audit trail', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
    expect(res.status).toBe(200);

    const payload = 'x'.repeat(4096);
    res.socket!.write(payload);
    await readN(res.socket!, payload.length);

    // Close and let the forwarder settle so the record is written.
    res.socket!.destroy();
    await waitForAsync(async () =>
      (await audit.recent()).some((r) => (r.bytesUp ?? 0) >= payload.length),
    );

    const record = (await audit.recent()).find((r) => (r.bytesUp ?? 0) >= payload.length);
    expect(record?.bytesDown).toBeGreaterThanOrEqual(payload.length);
    expect(record?.appId).toBe('wiki');
  });

  it('denies an app the user has no rule for', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect(`127.0.0.1:${payrollPort}`, session);
    expect(res.status).toBe(403);
  });

  it('allows a different user the app their group grants', async () => {
    const session = await sessions.create(bob, 60_000);
    const res = await proxyConnect(`127.0.0.1:${payrollPort}`, session);
    expect(res.status).toBe(200);
    res.socket!.destroy();
  });

  it('challenges with 407 when no credentials are supplied', async () => {
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`);
    expect(res.status).toBe(407);
    expect(res.headers?.['proxy-authenticate']).toMatch(/Basic/);
  });

  it('challenges with 407 for a wrong secret rather than leaking 403', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, {
      proxyUser: session.proxyUser,
      proxySecret: 'not-the-secret',
    });
    expect(res.status).toBe(407);
  });

  it('rejects a revoked session', async () => {
    const session = await sessions.create(alice, 60_000);
    await sessions.revokeBySubject(alice.sub);
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
    expect(res.status).toBe(407);
  });

  it('denies a host that is in no app at all', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect('169.254.169.254:80', session);
    expect(res.status).toBe(403);
  });

  it('writes an audit record naming the identity, app and rule', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
    res.socket?.destroy();

    const record = (await audit.recent()).find((r) => r.effect === 'allow' && r.appId === 'wiki');
    expect(record).toMatchObject({
      effect: 'allow',
      outcome: 'established',
      sub: 'u-alice',
      appId: 'wiki',
      ruleId: 'employees-wiki',
      connectorId: 'dc1',
    });
  });
});

describe('plain HTTP through the proxy (absolute-form, no CONNECT)', () => {
  it('proxies a GET and preserves path and query', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyGet(`http://127.0.0.1:${httpAppPort}/page?x=1&y=2`, session);

    expect(res.status).toBe(200);
    expect(res.body).toContain('method=GET');
    expect(res.body).toContain('url=/page?x=1&y=2');
    // The origin must see the app's own Host, not the proxy's.
    expect(res.body).toContain(`host=127.0.0.1:${httpAppPort}`);
  });

  it('forwards a request body', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyGet(`http://127.0.0.1:${httpAppPort}/submit`, session, {
      method: 'POST',
      body: 'hello=world',
    });

    expect(res.status).toBe(200);
    expect(res.body).toContain('method=POST');
    expect(res.body).toContain('body=hello=world');
  });

  it('does not leak the proxy credentials to the origin', async () => {
    const session = await sessions.create(alice, 60_000);
    const res = await proxyGet(`http://127.0.0.1:${httpAppPort}/`, session);
    expect(res.body).not.toContain(session.proxySecret);
    expect(res.body.toLowerCase()).not.toContain('proxy-authorization');
  });

  it('denies an identity with no rule for the app', async () => {
    const session = await sessions.create(bob, 60_000);
    const res = await proxyGet(`http://127.0.0.1:${httpAppPort}/`, session);
    expect(res.status).toBe(403);
  });

  it('challenges with 407 when credentials are missing', async () => {
    const res = await proxyGet(`http://127.0.0.1:${httpAppPort}/`);
    expect(res.status).toBe(407);
    expect(res.headers?.['proxy-authenticate']).toMatch(/Basic/);
  });

  it('audits the access with byte counts, like the CONNECT path', async () => {
    const session = await sessions.create(alice, 60_000);
    await proxyGet(`http://127.0.0.1:${httpAppPort}/audited`, session);

    await waitForAsync(async () =>
      (await audit.recent()).some((r) => r.appId === 'plain' && (r.bytesDown ?? 0) > 0),
    );
    const record = (await audit.recent()).find((r) => r.appId === 'plain' && (r.bytesDown ?? 0) > 0);
    expect(record).toMatchObject({ effect: 'allow', outcome: 'established' });
    expect(record?.bytesUp ?? 0).toBeGreaterThan(0);
    expect(record?.durationMs).toBeTypeOf('number');
  });
});

describe('session store outage', () => {
  it('answers 503, not 407, when the store is unreachable', async () => {
    const session = await sessions.create(alice, 60_000);

    // Break the store the way a Redis outage would.
    const original = sessions.resolve.bind(sessions);
    (sessions as unknown as { resolve: unknown }).resolve = () =>
      Promise.reject(new Error('ECONNREFUSED'));

    try {
      const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);

      // 407 would send every user round the sign-in loop against an IdP that
      // is perfectly healthy; a dropped socket would look like a network fault.
      expect(res.status).toBe(503);
      expect(res.headers?.['retry-after']).toBeDefined();

      const record = (await audit.recent()).find((r) => r.reason === 'store-unavailable');
      expect(record).toMatchObject({ outcome: 'unavailable', status: 503 });
    } finally {
      (sessions as unknown as { resolve: unknown }).resolve = original;
    }
  });

  it('does not count an outage against the caller\'s rate limit', async () => {
    const session = await sessions.create(alice, 60_000);
    const original = sessions.resolve.bind(sessions);
    (sessions as unknown as { resolve: unknown }).resolve = () =>
      Promise.reject(new Error('ECONNREFUSED'));

    try {
      // Far more than the limit of 3; none of these are the caller's fault.
      for (let i = 0; i < 6; i += 1) {
        const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
        expect(res.status).toBe(503);
      }
    } finally {
      (sessions as unknown as { resolve: unknown }).resolve = original;
    }

    // Once the store recovers the user is served immediately, not throttled.
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
    expect(res.status).toBe(200);
    res.socket?.destroy();
  });
});

describe('brute-force protection', () => {
  it('throttles repeated bad proxy credentials with 429', async () => {
    const bad = { proxyUser: 'guess', proxySecret: 'wrong' };

    // The limit is 3 failures per window.
    for (let i = 0; i < 3; i += 1) {
      const res = await proxyConnect(`127.0.0.1:${wikiPort}`, bad);
      expect(res.status).toBe(407);
    }

    const throttled = await proxyConnect(`127.0.0.1:${wikiPort}`, bad);
    expect(throttled.status).toBe(429);
    expect(throttled.headers?.['retry-after']).toBeDefined();

    // The audit trail must show why access stopped.
    expect((await audit.recent()).some((r) => r.reason === 'rate-limited')).toBe(true);
  });

  it('lets a valid credential through and clears the counter', async () => {
    // Still inside the window from the previous test, but a good credential is
    // never thrown away — throttling only counts failures.
    const session = await sessions.create(alice, 60_000);
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
    expect(res.status).toBe(200);
    res.socket?.destroy();
  });
});

describe('connector outage', () => {
  it('fails fast with 502 instead of hanging when the connector is gone', async () => {
    const session = await sessions.create(alice, 60_000);
    connectorSocket.destroy();
    await waitFor(() => registry.get('dc1') === undefined);

    const started = Date.now();
    const res = await proxyConnect(`127.0.0.1:${wikiPort}`, session);
    expect(res.status).toBe(502);
    // The point of failing fast: the user sees an error, not a hung tab.
    expect(Date.now() - started).toBeLessThan(3000);

    // Policy said allow, but no access occurred. The audit trail must not
    // count this as a successful access.
    const record = (await audit.recent())[0];
    expect(record).toMatchObject({ effect: 'allow', outcome: 'unavailable', status: 502 });
  });
});

// ---------------------------------------------------------------- helpers

interface ProxyResponse {
  status: number;
  socket?: net.Socket;
  headers?: http.IncomingHttpHeaders;
}

function proxyConnect(
  target: string,
  creds?: { proxyUser: string; proxySecret: string },
): Promise<ProxyResponse> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (creds) {
      const basic = Buffer.from(`${creds.proxyUser}:${creds.proxySecret}`).toString('base64');
      headers['proxy-authorization'] = `Basic ${basic}`;
    }

    const req = http.request({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'CONNECT',
      path: target,
      headers,
    });

    req.on('connect', (res, socket) => resolve({ status: res.statusCode ?? 0, socket, headers: res.headers }));
    req.on('response', (res) => {
      res.resume();
      resolve({ status: res.statusCode ?? 0, headers: res.headers });
    });
    req.on('error', reject);
    req.end();
  });
}

/** Issue an ordinary (absolute-form) proxied request — no CONNECT. */
function proxyGet(
  target: string,
  creds?: { proxyUser: string; proxySecret: string },
  opts: { method?: string; body?: string } = {},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    const headers: Record<string, string> = { host: url.host };
    if (creds) {
      const basic = Buffer.from(`${creds.proxyUser}:${creds.proxySecret}`).toString('base64');
      headers['proxy-authorization'] = `Basic ${basic}`;
    }
    if (opts.body) headers['content-length'] = String(Buffer.byteLength(opts.body));

    const req = http.request(
      {
        host: '127.0.0.1',
        port: proxyPort,
        method: opts.method ?? 'GET',
        path: target, // absolute-form
        headers,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => {
          body += c;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }));
      },
    );
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function echoServer(): Promise<{ port: number; close: () => void }> {
  const server = net.createServer((socket) => socket.pipe(socket));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    port: (server.address() as AddressInfo).port,
    close: () => server.close(),
  };
}

function readN(stream: NodeJS.ReadableStream, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= n) {
        stream.removeListener('data', onData);
        resolve(Buffer.concat(chunks));
      }
    };
    stream.on('data', onData);
    stream.on('error', reject);
  });
}

async function waitForAsync(
  predicate: () => Promise<boolean>,
  timeoutMs = 5000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met within timeout');
}

async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met within timeout');
}
