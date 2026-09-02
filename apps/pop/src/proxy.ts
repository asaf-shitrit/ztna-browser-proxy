import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { Duplex } from 'node:stream';
import { forwardDuplex } from '@ztna/tunnel';
import type { Policy, Identity, Decision } from '@ztna/policy';
import type { ConnectorRegistry } from './registry.js';
import type { OwnershipRegistry } from './ownership.js';
import type { MeshClient } from './mesh.js';
import type { SessionStore } from './sessions.js';
import { AuditLog, log } from './audit.js';
import { RateLimiter } from './rate-limit.js';

export interface ProxyOptions {
  port: number;
  /** Failed-auth throttle. Supplied by the caller so it can be shared/tested. */
  authLimiter?: RateLimiter;
  cert?: Buffer | undefined;
  key?: Buffer | undefined;
  policy: () => Policy;
  registry: ConnectorRegistry;
  sessions: SessionStore;
  audit: AuditLog;
  /** Set for multi-POP deployments; omitted means every connector is local. */
  ownership?: OwnershipRegistry | undefined;
  mesh?: MeshClient | undefined;
  /** This POP's own mesh address, to recognise a stale self-lease. */
  meshAddress?: string | undefined;
}

/**
 * The browser-facing proxy listener.
 *
 * ALPN advertises http/1.1 only. Chrome will happily negotiate HTTP/2 to a
 * proxy if offered, but ALPN is the *client's* choice, so offering both would
 * mean maintaining two proxy code paths rather than one. HTTP/1.1 also gives
 * each tunnelled app its own TCP connection, avoiding the head-of-line blocking
 * that a shared h2 connection would impose on a lossy last-mile link — the
 * exact conditions ZTNA clients run under. Adding an h2 client leg later is a
 * thin adapter over `forwardToApp`, which is transport-agnostic by design.
 */
/**
 * Source address of a connection, used as the throttle key. Not spoofable at
 * the TCP level, and deliberately not taken from a header — X-Forwarded-For on
 * a proxy request is attacker-controlled and would let one client evade the
 * limit or lock out another.
 */
function sourceKey(socket: { remoteAddress?: string | undefined } | null): string {
  return socket?.remoteAddress ?? 'unknown';
}

export function startProxy(options: ProxyOptions): http.Server | https.Server {
  const server =
    options.cert && options.key
      ? https.createServer({
          cert: options.cert,
          key: options.key,
          ALPNProtocols: ['http/1.1'],
        })
      : http.createServer();

  // HTTPS (and WebSocket) apps arrive as CONNECT.
  server.on('connect', (req, clientSocket: Duplex, head: Buffer) => {
    void handleConnect(req, clientSocket, head, options).catch((err: unknown) => {
      log('error', 'connect handler failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      clientSocket.destroy();
    });
  });

  // Plain-HTTP apps arrive as an absolute-form request.
  server.on('request', (req, res) => {
    void handleAbsoluteForm(req, res, options).catch((err: unknown) => {
      log('error', 'request handler failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });

  server.on('clientError', (_err, socket) => {
    (socket as net.Socket).destroy();
  });

  server.listen(options.port, '0.0.0.0', () => {
    log('info', 'proxy listener ready', {
      port: options.port,
      tls: Boolean(options.cert),
      alpn: ['http/1.1'],
    });
  });

  return server;
}

/**
 * Everything that must happen before a byte moves, for either proxy mode:
 * authenticate, throttle, authorize, and open the upstream — auditing each
 * outcome.
 *
 * Shared so CONNECT and absolute-form cannot diverge on any of it. They differ
 * only in how a refusal is rendered on the wire, which is the caller's job.
 */
type Gate =
  | { ok: true; stream: Duplex; identity: Identity; decision: Decision }
  | { ok: false; status: number; message: string; headers: Record<string, string> };

async function authorizeAndOpen(
  req: http.IncomingMessage,
  key: string,
  target: { host: string; port: number },
  options: ProxyOptions,
): Promise<Gate> {
  const auth = await authenticate(req.headers['proxy-authorization'], options);
  if (!auth.ok) {
    const rejection = rejectAuth(auth.reason, key, target, options);
    return { ok: false, ...rejection };
  }

  // A success clears the counter, so a user who mistypes once then succeeds is
  // never throttled.
  options.authLimiter?.clear(key);

  const decision = options.policy().evaluate({
    identity: auth.identity,
    host: target.host,
    port: target.port,
  });

  if (decision.effect === 'deny') {
    options.audit.decision(auth.identity, target, decision, { status: 403, outcome: 'blocked' });
    return { ok: false, status: 403, message: 'Forbidden', headers: {} };
  }

  const upstream = await openUpstream(decision, target, options);
  if (!upstream.ok) {
    options.audit.decision(auth.identity, target, decision, {
      status: upstream.status,
      outcome: 'unavailable',
    });
    return { ok: false, status: upstream.status, message: upstream.message, headers: {} };
  }

  return { ok: true, stream: upstream.stream, identity: auth.identity, decision };
}

async function handleConnect(
  req: http.IncomingMessage,
  clientSocket: Duplex,
  head: Buffer,
  options: ProxyOptions,
): Promise<void> {
  const target = parseHostPort(req.url ?? '', 443);
  if (!target) {
    writeRaw(clientSocket, 400, 'Bad Request');
    return;
  }

  const key = sourceKey(clientSocket as unknown as { remoteAddress?: string });
  const gate = await authorizeAndOpen(req, key, target, options);

  if (!gate.ok) {
    writeRaw(clientSocket, gate.status, gate.message, gate.headers);
    return;
  }

  const { stream: upstreamStream, identity, decision } = gate;

  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  if (head.length > 0) upstreamStream.write(head);

  const { bytesUp, bytesDown, durationMs } = await forwardToApp(clientSocket, upstreamStream);

  options.audit.decision(identity, target, decision, {
    status: 200,
    outcome: 'established',
    bytesUp,
    bytesDown,
    durationMs,
  });
}

/**
 * The transport-agnostic forwarding core. It takes any client-side duplex — a
 * raw socket today, an Http2Stream if we ever enable an h2 client leg — and
 * pumps it against the tunnel stream. Keeping this free of HTTP/1.1 specifics
 * is what makes that future change additive rather than a rewrite.
 */
export function forwardToApp(
  client: Duplex,
  upstream: Duplex,
): Promise<{ bytesUp: number; bytesDown: number; durationMs: number }> {
  return forwardDuplex(client, upstream);
}

interface AuthRejection {
  status: number;
  headers: Record<string, string>;
  message: string;
}

/**
 * Decide how to answer a failed proxy authentication, and audit it.
 *
 * Shared by both proxy paths so CONNECT and absolute-form cannot drift: they
 * must throttle the same attempts, distinguish an outage from a bad credential
 * the same way, and produce the same audit trail. Only the rendering differs.
 */
function rejectAuth(
  reason: 'missing-credentials' | 'invalid-credentials' | 'store-unavailable',
  key: string,
  target: { host: string; port: number },
  options: ProxyOptions,
): AuthRejection {
  const audit = (outcome: 'blocked' | 'unavailable', status: number, why: string): void => {
    options.audit.record({
      effect: 'deny',
      outcome,
      reason: why,
      host: target.host,
      port: target.port,
      status,
    });
  };

  // A store outage is not the caller's fault: it must not be answered with 407
  // (which would loop every user through sign-in against a healthy IdP), and
  // must not count against their rate limit.
  if (reason === 'store-unavailable') {
    audit('unavailable', 503, reason);
    return {
      status: 503,
      headers: { 'Retry-After': '5' },
      message: 'session store unavailable',
    };
  }

  const decision = options.authLimiter?.hit(key);
  if (decision && !decision.allowed) {
    audit('blocked', 429, 'rate-limited');
    return {
      status: 429,
      headers: { 'Retry-After': String(Math.ceil(decision.retryAfterMs / 1000)) },
      message: 'too many failed authentication attempts',
    };
  }

  audit('blocked', 407, reason);
  return {
    status: 407,
    headers: { 'Proxy-Authenticate': 'Basic realm="ztna"' },
    message: 'proxy authentication required',
  };
}

type UpstreamResult =
  | { ok: true; stream: Duplex }
  | { ok: false; status: number; message: string };

/** Map a connector/peer status onto what the browser should be told. */
function upstreamFailure(status: number): UpstreamResult {
  return status === 504
    ? { ok: false, status: 504, message: 'Gateway Timeout' }
    : { ok: false, status: 502, message: 'Bad Gateway' };
}

function offline(decision: Decision, connectorId: string, owner?: string | null): UpstreamResult {
  // Fail fast and loudly: a missing connector is an outage, not a policy
  // decision, and hanging here would look like a broken app to the user.
  log('warn', 'no live connector for app', { appId: decision.appId, connectorId, owner });
  return { ok: false, status: 502, message: 'Bad Gateway (connector offline)' };
}

/** This POP holds the connector: open the stream directly. */
async function openLocally(
  connector: NonNullable<ReturnType<ConnectorRegistry['get']>>,
  connectorId: string,
  target: { host: string; port: number },
): Promise<UpstreamResult> {
  try {
    const { stream, status } = await connector.client.openStream(target.host, target.port);
    if (status !== 200) return upstreamFailure(status);
    return { ok: true, stream: stream as unknown as Duplex };
  } catch (err) {
    log('warn', 'failed to open tunnel stream', {
      connectorId,
      error: err instanceof Error ? err.message : String(err),
    });
    return { ok: false, status: 502, message: 'Bad Gateway' };
  }
}

/** Another POP holds the connector: forward the stream to it. */
async function openViaPeer(
  decision: Decision,
  connectorId: string,
  target: { host: string; port: number },
  options: ProxyOptions,
): Promise<UpstreamResult> {
  if (!options.ownership || !options.mesh) return offline(decision, connectorId);

  const owner = await options.ownership.lookup(connectorId);

  // A lease naming us, with no local session behind it, is stale — the
  // connector dropped and the key has not expired yet. Forwarding to ourselves
  // would loop.
  if (!owner || owner === options.meshAddress) return offline(decision, connectorId, owner);

  try {
    const { stream, status } = await options.mesh.openStream({
      peerAddress: owner,
      connectorId,
      host: target.host,
      port: target.port,
    });
    if (status !== 200) return upstreamFailure(status);

    log('info', 'forwarded via peer pop', { connectorId, owner });
    return { ok: true, stream };
  } catch (err) {
    log('warn', 'mesh forward failed', {
      connectorId,
      owner,
      error: err instanceof Error ? err.message : String(err),
    });
    return { ok: false, status: 502, message: 'Bad Gateway' };
  }
}

async function openUpstream(
  decision: Decision,
  target: { host: string; port: number },
  options: ProxyOptions,
): Promise<UpstreamResult> {
  const connectorId = decision.connectorId;
  if (!connectorId) return { ok: false, status: 502, message: 'Bad Gateway' };

  // Fast path first, deliberately: with clients and connectors both attaching
  // to the nearest POP, the connector is usually right here, and that case
  // must not pay a Redis round trip on every CONNECT.
  const local = options.registry.get(connectorId);
  if (local) return openLocally(local, connectorId, target);

  return openViaPeer(decision, connectorId, target, options);
}

/** Re-emit the client's request in origin form, down the tunnel. */
function writeOriginRequest(
  req: http.IncomingMessage,
  url: URL,
  upstream: Duplex,
): number {
  const headers = { ...req.headers };
  // Hop-by-hop headers: the proxy credential is ours, not the app's, and
  // keep-alive is negotiated per hop.
  delete headers['proxy-authorization'];
  delete headers['proxy-connection'];
  headers['connection'] = 'close';

  const head = [
    `${req.method} ${url.pathname}${url.search} HTTP/1.1`,
    ...Object.entries(headers).map(
      ([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`,
    ),
    '',
    '',
  ].join('\r\n');

  upstream.write(head);
  return Buffer.byteLength(head);
}

/**
 * Pump the exchange and audit it once it settles.
 *
 * forwardDuplex is deliberately not reused: Node's HTTP server still owns this
 * socket for keep-alive, and hijacking it would break connection reuse for the
 * next request on the same proxy connection.
 */
function relayOriginResponse(
  ctx: {
    req: http.IncomingMessage;
    socket: Duplex;
    upstream: Duplex;
    bytesUpInitial: number;
  },
  audit: (outcome: 'established' | 'unavailable', status: number, bytes: Bytes) => void,
): void {
  const startedAt = Date.now();
  let bytesUp = ctx.bytesUpInitial;
  let bytesDown = 0;
  let recorded = false;

  const settle = (outcome: 'established' | 'unavailable', status: number): void => {
    if (recorded) return;
    recorded = true;
    audit(outcome, status, { bytesUp, bytesDown, durationMs: Date.now() - startedAt });
  };

  ctx.req.on('data', (chunk: Buffer) => {
    bytesUp += chunk.length;
  });
  ctx.upstream.on('data', (chunk: Buffer) => {
    bytesDown += chunk.length;
  });

  ctx.req.pipe(ctx.upstream, { end: false });
  ctx.upstream.pipe(ctx.socket);

  ctx.upstream.on('end', () => {
    ctx.socket.end();
    settle('established', 200);
  });
  ctx.upstream.on('close', () => settle('established', 200));
  ctx.upstream.on('error', () => {
    settle('unavailable', 502);
    ctx.socket.destroy();
  });
}

interface Bytes {
  bytesUp: number;
  bytesDown: number;
  durationMs: number;
}

async function handleAbsoluteForm(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: ProxyOptions,
): Promise<void> {
  // Absolute-form: `GET http://wiki.internal/path HTTP/1.1`
  let url: URL;
  try {
    url = new URL(req.url ?? '');
  } catch {
    res.writeHead(400).end('proxy requests must use absolute-form URLs');
    return;
  }

  const target = { host: url.hostname, port: Number(url.port || 80) };
  const key = sourceKey(req.socket);
  const gate = await authorizeAndOpen(req, key, target, options);

  if (!gate.ok) {
    res.writeHead(gate.status, gate.headers).end(gate.message);
    return;
  }

  const socket = res.socket;
  if (!socket) {
    gate.stream.destroy();
    return;
  }

  const bytesUpInitial = writeOriginRequest(req, url, gate.stream);

  relayOriginResponse(
    { req, socket, upstream: gate.stream, bytesUpInitial },
    (outcome, status, bytes) => {
      // `status` is the POP's proxy-level result, not the application's. The
      // POP does not parse the upstream response, and deliberately so — it has
      // no business reading app traffic. A 404 from the app is still a
      // successful brokered access as far as this audit trail is concerned.
      options.audit.decision(gate.identity, target, gate.decision, { status, outcome, ...bytes });
    },
  );
}

type AuthResult =
  | { ok: true; identity: Identity }
  | {
      ok: false;
      reason: 'missing-credentials' | 'invalid-credentials' | 'store-unavailable';
    };

async function authenticate(
  header: string | undefined,
  options: ProxyOptions,
): Promise<AuthResult> {
  if (!header?.startsWith('Basic ')) return { ok: false, reason: 'missing-credentials' };

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const sep = decoded.indexOf(':');
  if (sep < 0) return { ok: false, reason: 'invalid-credentials' };

  let session;
  try {
    session = await options.sessions.resolve(decoded.slice(0, sep), decoded.slice(sep + 1));
  } catch (err) {
    // A session store outage is not a credential problem. Answering 407 would
    // send every user round the sign-in loop against an IdP that is fine, and
    // dropping the socket would look like a network fault. Say so plainly.
    log('error', 'session store unavailable', {
      error: err instanceof Error ? err.message : String(err),
    });
    return { ok: false, reason: 'store-unavailable' };
  }

  // An expired or revoked session returns 407 rather than 403, so Chrome
  // re-prompts for credentials and the extension can supply a fresh secret.
  if (!session) return { ok: false, reason: 'invalid-credentials' };

  return { ok: true, identity: session.identity };
}

export function parseHostPort(
  value: string,
  defaultPort: number,
): { host: string; port: number } | null {
  if (!value) return null;

  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
  if (bracketed) {
    const host = bracketed[1];
    if (!host) return null;
    return { host, port: bracketed[2] ? Number(bracketed[2]) : defaultPort };
  }

  const idx = value.lastIndexOf(':');
  if (idx < 0) return { host: value, port: defaultPort };

  const host = value.slice(0, idx);
  const port = Number(value.slice(idx + 1));
  if (!host || host.includes(':') || !Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }
  return { host, port };
}

function writeRaw(
  socket: Duplex,
  status: number,
  message: string,
  headers: Record<string, string> = {},
): void {
  const head = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}\r\n`)
    .join('');
  socket.write(`HTTP/1.1 ${status} ${message}\r\n${head}Content-Length: 0\r\n\r\n`);
  socket.end();
}
