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
  const auth = await authenticate(req.headers['proxy-authorization'], options);

  if (!auth.ok) {
    const decision = options.authLimiter?.hit(key);
    if (decision && !decision.allowed) {
      options.audit.record({
        effect: 'deny',
        outcome: 'blocked',
        reason: 'rate-limited',
        host: target.host,
        port: target.port,
        status: 429,
      });
      writeRaw(clientSocket, 429, 'Too Many Requests', {
        'Retry-After': String(Math.ceil(decision.retryAfterMs / 1000)),
      });
      return;
    }

    options.audit.record({
      effect: 'deny',
      outcome: 'blocked',
      reason: auth.reason,
      host: target.host,
      port: target.port,
      status: 407,
    });
    writeRaw(clientSocket, 407, 'Proxy Authentication Required', {
      'Proxy-Authenticate': 'Basic realm="ztna"',
    });
    return;
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
    options.audit.decision(auth.identity, target, decision, {
      status: 403,
      outcome: 'blocked',
    });
    writeRaw(clientSocket, 403, 'Forbidden');
    return;
  }

  const upstream = await openUpstream(decision, target, options);
  if (!upstream.ok) {
    options.audit.decision(auth.identity, target, decision, {
      status: upstream.status,
      outcome: 'unavailable',
    });
    writeRaw(clientSocket, upstream.status, upstream.message);
    return;
  }

  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  if (head.length > 0) upstream.stream.write(head);

  const { bytesUp, bytesDown, durationMs } = await forwardToApp(clientSocket, upstream.stream);

  options.audit.decision(auth.identity, target, decision, {
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

async function openUpstream(
  decision: Decision,
  target: { host: string; port: number },
  options: ProxyOptions,
): Promise<
  | { ok: true; stream: Duplex }
  | { ok: false; status: number; message: string }
> {
  const connectorId = decision.connectorId;
  if (!connectorId) {
    return { ok: false, status: 502, message: 'Bad Gateway' };
  }

  // Fast path: this POP holds the connector. Deliberately checked BEFORE any
  // ownership lookup — with clients and connectors both attaching to the
  // nearest POP this is the common case, and it must not pay a Redis round
  // trip on every CONNECT.
  const local = options.registry.get(connectorId);
  if (local) {
    try {
      const { stream, status } = await local.client.openStream(target.host, target.port);
      if (status !== 200) {
        return {
          ok: false,
          status: status === 504 ? 504 : 502,
          message: status === 504 ? 'Gateway Timeout' : 'Bad Gateway',
        };
      }
      return { ok: true, stream: stream as unknown as Duplex };
    } catch (err) {
      log('warn', 'failed to open tunnel stream', {
        connectorId,
        error: err instanceof Error ? err.message : String(err),
      });
      return { ok: false, status: 502, message: 'Bad Gateway' };
    }
  }

  // Slow path: some other POP may hold it.
  if (!options.ownership || !options.mesh) {
    log('warn', 'no live connector for app', { appId: decision.appId, connectorId });
    return { ok: false, status: 502, message: 'Bad Gateway (connector offline)' };
  }

  const owner = await options.ownership.lookup(connectorId);

  // A lease naming us, with no local session behind it, is stale — the
  // connector dropped and the key has not expired yet. Forwarding to ourselves
  // would loop.
  if (!owner || owner === options.meshAddress) {
    log('warn', 'no live connector for app', { appId: decision.appId, connectorId, owner });
    return { ok: false, status: 502, message: 'Bad Gateway (connector offline)' };
  }

  try {
    const { stream, status } = await options.mesh.openStream(
      owner,
      connectorId,
      target.host,
      target.port,
    );
    if (status !== 200) {
      return {
        ok: false,
        status: status === 504 ? 504 : 502,
        message: status === 504 ? 'Gateway Timeout' : 'Bad Gateway',
      };
    }
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
  const auth = await authenticate(req.headers['proxy-authorization'], options);

  if (!auth.ok) {
    const decision = options.authLimiter?.hit(key);
    if (decision && !decision.allowed) {
      options.audit.record({
        effect: 'deny',
        outcome: 'blocked',
        reason: 'rate-limited',
        host: target.host,
        port: target.port,
        status: 429,
      });
      res
        .writeHead(429, { 'Retry-After': String(Math.ceil(decision.retryAfterMs / 1000)) })
        .end('too many failed authentication attempts');
      return;
    }

    options.audit.record({
      effect: 'deny',
      outcome: 'blocked',
      reason: auth.reason,
      host: target.host,
      port: target.port,
      status: 407,
    });
    res
      .writeHead(407, { 'Proxy-Authenticate': 'Basic realm="ztna"' })
      .end('proxy authentication required');
    return;
  }

  options.authLimiter?.clear(key);

  const decision = options.policy().evaluate({
    identity: auth.identity,
    host: target.host,
    port: target.port,
  });

  if (decision.effect === 'deny') {
    options.audit.decision(auth.identity, target, decision, {
      status: 403,
      outcome: 'blocked',
    });
    res.writeHead(403).end('forbidden');
    return;
  }

  const upstream = await openUpstream(decision, target, options);
  if (!upstream.ok) {
    options.audit.decision(auth.identity, target, decision, {
      status: upstream.status,
      outcome: 'unavailable',
    });
    res.writeHead(upstream.status).end(upstream.message);
    return;
  }

  // Re-emit the request in origin form down the tunnel.
  const headers = { ...req.headers };
  delete headers['proxy-authorization'];
  delete headers['proxy-connection'];
  headers['connection'] = 'close';

  const lines = [
    `${req.method} ${url.pathname}${url.search} HTTP/1.1`,
    ...Object.entries(headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`),
    '',
    '',
  ];
  const head = lines.join('\r\n');
  upstream.stream.write(head);

  const socket = res.socket;
  if (!socket) {
    upstream.stream.destroy();
    return;
  }

  // Account for this request the same way the CONNECT path does, so the audit
  // trail is uniform across both. We cannot reuse forwardDuplex here: Node's
  // HTTP server still owns this socket for keep-alive, and hijacking it would
  // break connection reuse for the next request on the same proxy connection.
  const startedAt = Date.now();
  let bytesUp = Buffer.byteLength(head);
  let bytesDown = 0;

  req.on('data', (chunk: Buffer) => {
    bytesUp += chunk.length;
  });
  upstream.stream.on('data', (chunk: Buffer) => {
    bytesDown += chunk.length;
  });

  let recorded = false;
  const record = (outcome: 'established' | 'unavailable', status: number): void => {
    if (recorded) return;
    recorded = true;
    // `status` is the POP's proxy-level result, not the application's. The POP
    // does not parse the upstream response, and deliberately so — it has no
    // business reading app traffic. A 404 from the app is still a successful
    // brokered access as far as this audit trail is concerned.
    options.audit.decision(auth.identity, target, decision, {
      status,
      outcome,
      bytesUp,
      bytesDown,
      durationMs: Date.now() - startedAt,
    });
  };

  req.pipe(upstream.stream, { end: false });

  // Relay the raw upstream response bytes straight to the client socket.
  upstream.stream.pipe(socket);
  upstream.stream.on('end', () => {
    socket.end();
    record('established', 200);
  });
  upstream.stream.on('close', () => record('established', 200));
  upstream.stream.on('error', () => {
    record('unavailable', 502);
    socket.destroy();
  });
}

type AuthResult =
  | { ok: true; identity: Identity }
  | { ok: false; reason: 'missing-credentials' | 'invalid-credentials' };

async function authenticate(
  header: string | undefined,
  options: ProxyOptions,
): Promise<AuthResult> {
  if (!header?.startsWith('Basic ')) return { ok: false, reason: 'missing-credentials' };

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const sep = decoded.indexOf(':');
  if (sep < 0) return { ok: false, reason: 'invalid-credentials' };

  const session = await options.sessions.resolve(decoded.slice(0, sep), decoded.slice(sep + 1));
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
