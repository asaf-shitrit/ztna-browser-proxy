import type { Settings } from 'node:http2';

export const MB = 1024 * 1024;

/**
 * ALPN protocol for the tunnel's TLS connection.
 *
 * This is NOT optional when the tunnel runs over TLS. Node's HTTP/2 server
 * inspects `socket.alpnProtocol` on every incoming connection: a plain TCP
 * socket reports `undefined` and is accepted, but a TLS socket that negotiated
 * no ALPN reports `false`, which Node reads as a failed negotiation and
 * rejects with "Protocol error". Both ends must therefore agree on 'h2'.
 *
 * Covered by packages/tunnel/test/tls-handshake.test.ts.
 */
export const TUNNEL_ALPN = 'h2';

/**
 * Shared HTTP/2 settings for both ends of the tunnel.
 *
 * The defaults are tuned for browsers fetching a handful of resources, not for
 * a proxy carrying every connection of every user behind a connector.
 */
export const TUNNEL_SETTINGS: Settings = {
  // Default is 100. A single connector fronting a busy app will blow through
  // that instantly, and exceeding it silently queues streams.
  maxConcurrentStreams: 1000,
  // Default is 64 KiB, which throttles bulk transfers to roughly one window
  // per round trip. 1 MiB keeps a fast LAN app from being RTT-bound.
  initialWindowSize: 1 * MB,
};

/** Cap on total memory a single tunnel session may buffer. */
export const MAX_SESSION_MEMORY_MB = 64;

/** Interval for liveness PINGs on an idle tunnel. */
export const PING_INTERVAL_MS = 15_000;

/** How long to wait for a PING ack before declaring the tunnel dead. */
export const PING_TIMEOUT_MS = 10_000;
