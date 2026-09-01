import http2, { type ClientHttp2Session, type ClientHttp2Stream } from 'node:http2';
import type { Duplex } from 'node:stream';
import {
  TUNNEL_SETTINGS,
  MAX_SESSION_MEMORY_MB,
  PING_INTERVAL_MS,
  PING_TIMEOUT_MS,
  MB,
} from './settings.js';

/**
 * POP side of the role inversion described at the top of `serve.ts`.
 *
 * The POP *accepted* this socket, yet becomes the HTTP/2 client on it, because
 * the POP is the side that needs to open streams. `createConnection` is the
 * documented hook that lets us supply a socket instead of having Node dial one.
 *
 * We address the session as `http://` — the socket is already decrypted, so
 * this is plaintext h2 (h2c) as far as Node is concerned, matching
 * `http2.createServer()` on the connector side. The authority is nominal and
 * never resolved.
 */

export interface TunnelClientOptions {
  onError?: (err: Error) => void;
  onClose?: () => void;
  /** Set false in tests that drive time manually. */
  keepAlive?: boolean;
}

export interface OpenStreamResult {
  stream: ClientHttp2Stream;
  status: number;
}

export class TunnelClient {
  readonly session: ClientHttp2Session;
  #pingTimer: NodeJS.Timeout | undefined;
  #closed = false;

  constructor(socket: Duplex, options: TunnelClientOptions = {}) {
    this.session = http2.connect('http://connector.tunnel.invalid', {
      createConnection: () => socket,
      settings: TUNNEL_SETTINGS,
      maxSessionMemory: MAX_SESSION_MEMORY_MB,
    });

    // Raise the session-level flow-control window to match the per-stream one,
    // otherwise concurrent bulk streams contend for a 64 KiB session budget.
    this.session.on('connect', () => {
      this.session.setLocalWindowSize(16 * MB);
    });

    this.session.on('error', (err: unknown) => {
      options.onError?.(toError(err));
    });

    this.session.on('close', () => {
      this.#closed = true;
      this.#stopKeepAlive();
      options.onClose?.();
    });

    if (options.keepAlive !== false) {
      this.#startKeepAlive(options.onError);
    }
  }

  get closed(): boolean {
    return this.#closed || this.session.closed || this.session.destroyed;
  }

  /**
   * Open a tunnelled TCP stream to `host:port` inside the private network.
   * Resolves once the connector has answered with a status.
   */
  openStream(host: string, port: number, timeoutMs = 15_000): Promise<OpenStreamResult> {
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error('tunnel session is closed'));
        return;
      }

      // A CONNECT request carries :method and :authority only — no :scheme,
      // no :path. Node rejects the request if those are present.
      const stream = this.session.request(
        {
          [http2.constants.HTTP2_HEADER_METHOD]: 'CONNECT',
          [http2.constants.HTTP2_HEADER_AUTHORITY]: formatAuthority(host, port),
        },
        { endStream: false },
      );

      const timer = setTimeout(() => {
        cleanup();
        stream.close(http2.constants.NGHTTP2_CANCEL);
        reject(new Error(`timed out opening stream to ${host}:${port}`));
      }, timeoutMs);

      const cleanup = (): void => {
        clearTimeout(timer);
        stream.removeListener('response', onResponse);
        stream.removeListener('error', onError);
      };

      const onResponse = (headers: Record<string, unknown>): void => {
        cleanup();
        const status = Number(headers[http2.constants.HTTP2_HEADER_STATUS] ?? 0);
        resolve({ stream, status });
      };

      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };

      stream.on('response', onResponse);
      stream.on('error', onError);
    });
  }

  /** Issue a control request over the same session, e.g. `GET /catalog`. */
  request(method: string, path: string, timeoutMs = 10_000): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error('tunnel session is closed'));
        return;
      }

      const stream = this.session.request({
        [http2.constants.HTTP2_HEADER_METHOD]: method,
        [http2.constants.HTTP2_HEADER_PATH]: path,
        [http2.constants.HTTP2_HEADER_SCHEME]: 'http',
      });

      let status = 0;
      const chunks: Buffer[] = [];

      const timer = setTimeout(() => {
        stream.close(http2.constants.NGHTTP2_CANCEL);
        reject(new Error(`timed out on ${method} ${path}`));
      }, timeoutMs);

      stream.on('response', (headers) => {
        status = Number(headers[http2.constants.HTTP2_HEADER_STATUS] ?? 0);
      });
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => {
        clearTimeout(timer);
        resolve({ status, body: Buffer.concat(chunks).toString('utf8') });
      });
      stream.on('error', (err: unknown) => {
        clearTimeout(timer);
        reject(toError(err));
      });
    });
  }

  /** Graceful shutdown: GOAWAY, letting in-flight streams finish. */
  close(): void {
    this.#stopKeepAlive();
    if (!this.session.closed) {
      this.session.close();
    }
  }

  destroy(err?: Error): void {
    this.#stopKeepAlive();
    this.session.destroy(err);
  }

  #startKeepAlive(onError?: (err: Error) => void): void {
    this.#pingTimer = setInterval(() => {
      if (this.closed) {
        this.#stopKeepAlive();
        return;
      }
      const timer = setTimeout(() => {
        this.destroy(new Error('tunnel ping timed out'));
      }, PING_TIMEOUT_MS);

      try {
        this.session.ping((err) => {
          clearTimeout(timer);
          if (err) onError?.(err);
        });
      } catch (err) {
        clearTimeout(timer);
        onError?.(toError(err));
      }
    }, PING_INTERVAL_MS);

    this.#pingTimer.unref();
  }

  #stopKeepAlive(): void {
    if (this.#pingTimer) {
      clearInterval(this.#pingTimer);
      this.#pingTimer = undefined;
    }
  }
}

export function dialTunnel(socket: Duplex, options: TunnelClientOptions = {}): TunnelClient {
  return new TunnelClient(socket, options);
}

function formatAuthority(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

/** Node types many socket/stream `error` payloads as `any`. Narrow at the edge. */
function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}
