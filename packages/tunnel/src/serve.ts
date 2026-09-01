import http2, {
  type Http2Server,
  type ServerHttp2Stream,
  type IncomingHttpHeaders,
} from 'node:http2';
import type { Duplex } from 'node:stream';
import { TUNNEL_SETTINGS, MAX_SESSION_MEMORY_MB } from './settings.js';

/*
 * ============================================================================
 *                    !! THE ROLE INVERSION — READ THIS !!
 * ============================================================================
 *
 * This file makes the CONNECTOR an HTTP/2 *server* on a socket that the
 * connector itself *dialled out*. That looks backwards. It is deliberate.
 *
 * Two constraints collide:
 *   1. The connector must dial outbound. It lives in a private network with no
 *      inbound firewall rules and no public address. It is always the TCP
 *      client.
 *   2. The POP must open streams. Every browser CONNECT needs a fresh stream
 *      into the private network, and in HTTP/2 only the *client* may open a
 *      stream (server push is gone, and was never suitable for this anyway).
 *
 * If the connector were also the h2 client, the side that needs to initiate
 * would be the side that cannot. So we split the two roles apart:
 *
 *      TLS role:  connector = client,  POP = server   (satisfies constraint 1)
 *      h2  role:  connector = SERVER,  POP = CLIENT   (satisfies constraint 2)
 *
 * The seam is `http2.createServer()` — the *plaintext* h2 server — fed an
 * already-decrypted TLS socket via `server.emit('connection', socket)`.
 * Because TLS was terminated before h2 ever sees the socket, h2 has no idea
 * which side dialled, and we are free to assign the roles independently.
 *
 * Both `Http2Server.emit('connection', socket)` here and
 * `http2.connect({ createConnection })` on the POP side are public, documented
 * Node API. The *pairing* is unusual, not the primitives.
 *
 * DO NOT "fix" this into a conventional client/server arrangement. Doing so
 * either forces inbound connections to the private network (breaking the
 * entire security model) or requires hand-rolling a stream multiplexer to
 * reintroduce what HTTP/2 already gives us for free.
 *
 * Covered by packages/tunnel/test/inversion.test.ts.
 * ============================================================================
 */

/** Handles a non-CONNECT control request (e.g. `GET /catalog`). */
export type ControlHandler = (
  stream: ServerHttp2Stream,
  headers: IncomingHttpHeaders,
) => void | Promise<void>;

/** Handles a CONNECT stream targeting `host:port`. */
export type ConnectHandler = (
  stream: ServerHttp2Stream,
  target: { host: string; port: number },
) => void | Promise<void>;

export interface ServeTunnelOptions {
  /** Routed by `${method} ${path}`, e.g. `'GET /catalog'`. */
  control: Record<string, ControlHandler>;
  onConnect: ConnectHandler;
  onError?: (err: Error) => void;
}

export interface TunnelServer {
  readonly server: Http2Server;
  close(): void;
}

/**
 * Turn an already-established (and already-authenticated) socket into an
 * HTTP/2 server. Used by the connector on the socket it dialled to the POP.
 */
export function serveTunnel(socket: Duplex, options: ServeTunnelOptions): TunnelServer {
  const server = http2.createServer({
    settings: TUNNEL_SETTINGS,
    maxSessionMemory: MAX_SESSION_MEMORY_MB,
  });

  const fail = (err: Error): void => options.onError?.(err);

  server.on('stream', (stream, headers) => {
    void dispatch(stream, headers, options).catch((err: unknown) => {
      const error = err instanceof Error ? err : new Error(String(err));
      fail(error);
      if (!stream.closed) {
        stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
      }
    });
  });

  server.on('sessionError', fail);
  server.on('error', fail);

  // The inversion itself: hand our dialled socket to the h2 server as though
  // it had been accepted by a listener.
  server.emit('connection', socket);

  return {
    server,
    close: () => server.close(),
  };
}

async function dispatch(
  stream: ServerHttp2Stream,
  headers: IncomingHttpHeaders,
  options: ServeTunnelOptions,
): Promise<void> {
  const method = headers[http2.constants.HTTP2_HEADER_METHOD];

  if (method === 'CONNECT') {
    const authority = headers[http2.constants.HTTP2_HEADER_AUTHORITY];
    const target = parseAuthority(typeof authority === 'string' ? authority : undefined);
    if (!target) {
      stream.respond({ ':status': 400 });
      stream.end();
      return;
    }
    await options.onConnect(stream, target);
    return;
  }

  const path = headers[http2.constants.HTTP2_HEADER_PATH];
  const handler = options.control[`${String(method)} ${String(path)}`];
  if (!handler) {
    stream.respond({ ':status': 404 });
    stream.end();
    return;
  }
  await handler(stream, headers);
}

/** Parse an h2 `:authority` of the form `host:port`. IPv6 literals included. */
export function parseAuthority(
  authority: string | undefined,
): { host: string; port: number } | null {
  if (!authority) return null;

  // [::1]:443
  const bracketed = /^\[([^\]]+)\]:(\d+)$/.exec(authority);
  if (bracketed) {
    const host = bracketed[1];
    const port = Number(bracketed[2]);
    if (!host || !isValidPort(port)) return null;
    return { host, port };
  }

  const lastColon = authority.lastIndexOf(':');
  if (lastColon <= 0) return null;

  const host = authority.slice(0, lastColon);
  const port = Number(authority.slice(lastColon + 1));
  if (!host || host.includes(':') || !isValidPort(port)) return null;

  return { host, port };
}

function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= 65535;
}
