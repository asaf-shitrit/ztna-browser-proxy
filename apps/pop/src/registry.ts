import tls from 'node:tls';
import net from 'node:net';
import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  dialTunnel,
  readPreamble,
  catalogSchema,
  TUNNEL_ALPN,
  type TunnelClient,
  type Catalog,
} from '@ztna/tunnel';
import { log } from './audit.js';

/**
 * Registry of live connectors.
 *
 * The POP accepts the TCP connection but becomes the HTTP/2 *client* on it —
 * see the role-inversion comment in packages/tunnel/src/serve.ts. That is what
 * lets a connector sit behind a firewall with no inbound rules while the POP
 * still opens a stream per browser CONNECT.
 */

export interface RegisteredConnector {
  connectorId: string;
  client: TunnelClient;
  catalog: Catalog;
  connectedAt: number;
}

export class ConnectorRegistry {
  readonly #connectors = new Map<string, RegisteredConnector>();

  register(entry: RegisteredConnector): void {
    this.#connectors.get(entry.connectorId)?.client.destroy();
    this.#connectors.set(entry.connectorId, entry);
  }

  get(connectorId: string): RegisteredConnector | undefined {
    const entry = this.#connectors.get(connectorId);
    if (entry && entry.client.closed) {
      this.#connectors.delete(connectorId);
      return undefined;
    }
    return entry;
  }

  remove(connectorId: string, client: TunnelClient): void {
    // Only remove if it is still the same session; a reconnect may already
    // have replaced it.
    if (this.#connectors.get(connectorId)?.client === client) {
      this.#connectors.delete(connectorId);
    }
  }

  list(): RegisteredConnector[] {
    return [...this.#connectors.values()];
  }
}

export interface TunnelListenerOptions {
  port: number;
  /** Publishes which POP holds each connector, for multi-POP routing. */
  ownership?: import('./ownership.js').OwnershipRegistry | undefined;
  cert?: Buffer | undefined;
  key?: Buffer | undefined;
  connectorSecret: string;
  registry: ConnectorRegistry;
  /** Verify the connector's declared catalog against policy before trusting it. */
  validateCatalog?: (catalog: Catalog) => string | null;
}

/**
 * Listener for inbound connector tunnels. This is a raw TLS server, not an HTTP
 * server, because the accepted socket is handed straight to HTTP/2 with
 * inverted roles.
 */
export function startTunnelListener(options: TunnelListenerOptions): net.Server {
  const handle = (socket: net.Socket): void => {
    void handleConnector(socket, options).catch((err: unknown) => {
      log('warn', 'connector handshake failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      socket.destroy();
    });
  };

  const server =
    options.cert && options.key
      ? tls.createServer(
          {
            cert: options.cert,
            key: options.key,
            // Required: without a negotiated ALPN the connector's h2 server
            // rejects the socket. See TUNNEL_ALPN.
            ALPNProtocols: [TUNNEL_ALPN],
          },
          handle,
        )
      : net.createServer(handle);

  server.listen(options.port, '0.0.0.0', () => {
    log('info', 'tunnel listener ready', {
      port: options.port,
      tls: Boolean(options.cert),
    });
  });

  return server;
}

async function handleConnector(
  socket: net.Socket,
  options: TunnelListenerOptions,
): Promise<void> {
  socket.setNoDelay(true);

  // Authenticate before the socket becomes an HTTP/2 connection.
  const preamble = await readPreamble(socket);

  if (!verifyToken(preamble.connectorId, preamble.token, options.connectorSecret)) {
    log('warn', 'connector rejected: bad token', { connectorId: preamble.connectorId });
    socket.destroy();
    return;
  }

  const client = dialTunnel(socket, {
    onError: (err) =>
      log('warn', 'tunnel session error', {
        connectorId: preamble.connectorId,
        error: err.message,
      }),
    onClose: () => {
      options.registry.remove(preamble.connectorId, client);
      void options.ownership?.release(preamble.connectorId);
      log('warn', 'connector disconnected', { connectorId: preamble.connectorId });
    },
  });

  // Ask the connector what it serves, over the tunnel we just established.
  const res = await client.request('GET', '/catalog');
  if (res.status !== 200) {
    log('warn', 'connector catalog fetch failed', { status: res.status });
    client.destroy();
    return;
  }

  const catalog = catalogSchema.parse(JSON.parse(res.body));

  if (catalog.connectorId !== preamble.connectorId) {
    log('warn', 'connector id mismatch between preamble and catalog', {
      preamble: preamble.connectorId,
      catalog: catalog.connectorId,
    });
    client.destroy();
    return;
  }

  const problem = options.validateCatalog?.(catalog);
  if (problem) {
    log('warn', 'connector catalog rejected by policy', {
      connectorId: catalog.connectorId,
      problem,
    });
    client.destroy();
    return;
  }

  options.registry.register({
    connectorId: catalog.connectorId,
    client,
    catalog,
    connectedAt: Date.now(),
  });

  // Publish the lease only once the tunnel is actually usable, so a peer never
  // forwards to a POP that cannot serve the stream yet.
  await options.ownership?.claim(catalog.connectorId);

  log('info', 'connector registered', {
    connectorId: catalog.connectorId,
    apps: catalog.apps.map((a) => a.id),
  });
}

/**
 * Bootstrap tokens are HMACs of the connector id under a shared secret, so the
 * POP needs no per-connector database to validate one.
 */
export function mintToken(connectorId: string, secret: string): string {
  return createHmac('sha256', secret).update(connectorId).digest('base64url');
}

function verifyToken(connectorId: string, token: string, secret: string): boolean {
  const expected = Buffer.from(mintToken(connectorId, secret));
  const actual = Buffer.from(token);
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}
