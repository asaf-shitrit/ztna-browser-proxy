import http2, { type ClientHttp2Session, type ServerHttp2Stream } from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { timingSafeEqual } from 'node:crypto';
import type { Duplex } from 'node:stream';
import { forwardDuplex, parseAuthority, TUNNEL_SETTINGS } from '@ztna/tunnel';
import type { ConnectorRegistry } from './registry.js';
import { log } from './audit.js';

/**
 * POP-to-POP forwarding.
 *
 * When a client lands on a POP that does not hold the connector it needs, that
 * POP opens a stream to the POP that does and splices the two together. The
 * client's TLS session still terminates at the app, so the extra hop carries
 * ciphertext — no POP in the path can read the traffic.
 *
 * Unlike the connector tunnel, this needs no role inversion: the POP that wants
 * the stream is the one that dials, so it is naturally the HTTP/2 client.
 */

const CONNECTOR_HEADER = 'x-ztna-connector';
const AUTH_HEADER = 'x-ztna-mesh-auth';

export interface MeshListenerOptions {
  port: number;
  cert?: Buffer | undefined;
  key?: Buffer | undefined;
  /** CA that signs peer POP certificates. Enables mTLS when present. */
  ca?: Buffer | undefined;
  /**
   * Certificate common names permitted to forward through this POP.
   *
   * A CA-signed certificate alone is NOT sufficient identity: the same CA also
   * signs the demo app certificates, so anyone holding `wiki.internal`'s key
   * could otherwise authenticate as a peer POP. The allowlist is what makes
   * the client certificate mean "this specific POP".
   */
  peerCns?: string[] | undefined;
  /** Pre-shared fallback, used when mTLS is not configured (e.g. tests). */
  secret?: string | undefined;
  registry: ConnectorRegistry;
}

export function startMeshListener(options: MeshListenerOptions): net.Server {
  const handler = (stream: ServerHttp2Stream, headers: Record<string, unknown>): void => {
    void handleMeshStream(stream, headers, options).catch((err: unknown) => {
      log('warn', 'mesh stream failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      if (!stream.closed) stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
    });
  };

  const mutual = Boolean(options.cert && options.key && options.ca);

  const server =
    options.cert && options.key
      ? http2.createSecureServer({
          cert: options.cert,
          key: options.key,
          settings: TUNNEL_SETTINGS,
          ALPNProtocols: ['h2'],
          // Require and verify a peer certificate. TLS refuses the connection
          // outright, so an unauthenticated peer never reaches a stream.
          ...(mutual
            ? { ca: [options.ca!], requestCert: true, rejectUnauthorized: true }
            : {}),
        })
      : http2.createServer({ settings: TUNNEL_SETTINGS });

  server.on('stream', handler);
  if (mutual) {
    log('info', 'mesh requires client certificates', { peers: options.peerCns ?? [] });
  }
  server.on('sessionError', (err) => log('warn', 'mesh session error', { error: err.message }));

  server.listen(options.port, '0.0.0.0', () => {
    log('info', 'mesh listener ready', { port: options.port, tls: Boolean(options.cert) });
  });

  return server as unknown as net.Server;
}

async function handleMeshStream(
  stream: ServerHttp2Stream,
  headers: Record<string, unknown>,
  options: MeshListenerOptions,
): Promise<void> {
  const peer = authenticatePeer(stream, headers, options);
  if (!peer.ok) {
    log('warn', 'mesh auth rejected', { reason: peer.reason });
    stream.respond({ ':status': 401 });
    stream.end();
    return;
  }

  const connectorId = String(headers[CONNECTOR_HEADER] ?? '');
  const target = parseAuthority(String(headers[http2.constants.HTTP2_HEADER_AUTHORITY] ?? ''));
  if (!connectorId || !target) {
    stream.respond({ ':status': 400 });
    stream.end();
    return;
  }

  // Local registry ONLY. A peer must never forward onward: two POPs each
  // believing the other owns a connector would bounce the stream between them
  // until something timed out.
  const connector = options.registry.get(connectorId);
  if (!connector) {
    log('warn', 'mesh request for a connector we do not hold', { connectorId });
    stream.respond({ ':status': 502 });
    stream.end();
    return;
  }

  const { stream: upstream, status } = await connector.client.openStream(target.host, target.port);
  if (status !== 200) {
    stream.respond({ ':status': status });
    stream.end();
    return;
  }

  stream.respond({ ':status': 200 });
  log('info', 'serving forwarded stream for peer', { peer: peer.identity, connectorId });
  await forwardDuplex(stream as unknown as Duplex, upstream as unknown as Duplex);
}

type PeerAuth = { ok: true; identity: string } | { ok: false; reason: string };

/**
 * mTLS when a CA is configured, shared secret otherwise.
 *
 * TLS has already rejected any certificate the CA did not sign by the time we
 * get here; what remains is checking WHICH identity it is, because the CA signs
 * more than just POPs.
 */
function authenticatePeer(
  stream: ServerHttp2Stream,
  headers: Record<string, unknown>,
  options: MeshListenerOptions,
): PeerAuth {
  const socket = stream.session?.socket as TLSSocketLike | undefined;
  const usingMtls = Boolean(options.ca && options.peerCns);

  if (usingMtls) {
    const cert = socket?.getPeerCertificate?.();
    const cn = cert?.subject?.CN;
    if (!cn) return { ok: false, reason: 'no client certificate' };
    if (!options.peerCns!.includes(cn)) {
      return { ok: false, reason: `certificate CN '${cn}' is not a known peer` };
    }
    return { ok: true, identity: cn };
  }

  if (!options.secret) return { ok: false, reason: 'mesh auth not configured' };
  if (!constantTimeEquals(String(headers[AUTH_HEADER] ?? ''), options.secret)) {
    return { ok: false, reason: 'bad shared secret' };
  }
  return { ok: true, identity: 'shared-secret' };
}

interface TLSSocketLike {
  getPeerCertificate?: () => { subject?: { CN?: string } } | undefined;
}

export interface MeshClientOptions {
  /** Used only when mTLS is not configured. */
  secret?: string | undefined;
  ca?: Buffer | undefined;
  /** This POP's own certificate, presented to peers as its identity. */
  cert?: Buffer | undefined;
  key?: Buffer | undefined;
  tls: boolean;
  /** Verify peer certificates. Disable only for local development. */
  rejectUnauthorized?: boolean;
  /** Override the TLS server name when the peer address is not its cert name. */
  servername?: string | undefined;
}

/** Pools one HTTP/2 session per peer POP; streams multiplex over it. */
export class MeshClient {
  readonly #sessions = new Map<string, ClientHttp2Session>();

  constructor(private readonly options: MeshClientOptions) {}

  async openStream(
    peerAddress: string,
    connectorId: string,
    host: string,
    port: number,
    timeoutMs = 15_000,
  ): Promise<{ stream: Duplex; status: number }> {
    const session = this.#session(peerAddress);

    return new Promise((resolve, reject) => {
      const stream = session.request(
        {
          [http2.constants.HTTP2_HEADER_METHOD]: 'CONNECT',
          [http2.constants.HTTP2_HEADER_AUTHORITY]: host.includes(':')
            ? `[${host}]:${port}`
            : `${host}:${port}`,
          [CONNECTOR_HEADER]: connectorId,
          ...(this.options.secret ? { [AUTH_HEADER]: this.options.secret } : {}),
        },
        { endStream: false },
      );

      const timer = setTimeout(() => {
        cleanup();
        stream.close(http2.constants.NGHTTP2_CANCEL);
        reject(new Error(`timed out forwarding to ${peerAddress}`));
      }, timeoutMs);

      const cleanup = (): void => {
        clearTimeout(timer);
        stream.removeListener('response', onResponse);
        stream.removeListener('error', onError);
      };

      const onResponse = (h: Record<string, unknown>): void => {
        cleanup();
        resolve({
          stream: stream as unknown as Duplex,
          status: Number(h[http2.constants.HTTP2_HEADER_STATUS] ?? 0),
        });
      };
      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };

      stream.on('response', onResponse);
      stream.on('error', onError);
    });
  }

  #session(peerAddress: string): ClientHttp2Session {
    const existing = this.#sessions.get(peerAddress);
    if (existing && !existing.closed && !existing.destroyed) return existing;

    const scheme = this.options.tls ? 'https' : 'http';
    const session = http2.connect(`${scheme}://${peerAddress}`, {
      settings: TUNNEL_SETTINGS,
      ...(this.options.tls
        ? {
            ca: this.options.ca ? [this.options.ca] : undefined,
            // Our own identity, presented to the peer for mTLS.
            cert: this.options.cert,
            key: this.options.key,
            rejectUnauthorized: this.options.rejectUnauthorized ?? true,
            servername: this.options.servername,
          }
        : {}),
    });

    session.on('error', (err) => {
      log('warn', 'mesh peer session error', { peer: peerAddress, error: err.message });
      this.#sessions.delete(peerAddress);
    });
    session.on('close', () => this.#sessions.delete(peerAddress));

    this.#sessions.set(peerAddress, session);
    return session;
  }

  close(): void {
    for (const session of this.#sessions.values()) session.close();
    this.#sessions.clear();
  }
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

// Re-exported so tests can build a TLS peer without duplicating the options.
export { tls as _tls };
