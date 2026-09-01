import type { Duplex } from 'node:stream';

/**
 * Bidirectional byte pump between two duplexes, with a byte counter for audit.
 *
 * Deliberately transport-agnostic: it does not care whether either side is a
 * raw TCP socket (HTTP/1.1 CONNECT from the browser), an `Http2Stream` (the
 * tunnel), or an in-memory pair (tests). That is what keeps the POP's proxy
 * listener a thin adapter — adding an HTTP/2 client leg later means handing
 * this function an `Http2Stream` instead of a socket and changing nothing else.
 *
 * We do not use `stream.pipeline()` here: it destroys both streams on the first
 * end-of-stream, which would collapse a half-closed connection that still has
 * data to deliver in the other direction.
 */

export interface ForwardResult {
  bytesUp: number;
  bytesDown: number;
  /**
   * Time from start until the transfer actually ended — i.e. until the first
   * side went away — NOT until this promise settled. The two differ by the
   * peer drain grace below, which is teardown bookkeeping and would otherwise
   * show up as a spurious ~2s on every audited connection.
   */
  durationMs: number;
}

/**
 * How long the surviving side may keep flushing after its peer has gone.
 *
 * Waiting for BOTH sides to close is not sufficient: a keep-alive origin holds
 * its connection open indefinitely after answering, so a client that
 * disconnects would leave the tunnel stream open forever — leaking the stream
 * and, because the audit record is written when this resolves, silently losing
 * the record for every successful access.
 */
const PEER_DRAIN_MS = 2000;

export function forwardDuplex(client: Duplex, upstream: Duplex): Promise<ForwardResult> {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let endedAt: number | undefined;
    let bytesUp = 0;
    let bytesDown = 0;
    let settled = false;
    let drainTimer: NodeJS.Timeout | undefined;

    const finish = (): void => {
      if (settled) return;
      settled = true;
      if (drainTimer) clearTimeout(drainTimer);
      client.removeListener('error', onClientError);
      upstream.removeListener('error', onUpstreamError);
      resolve({
        bytesUp,
        bytesDown,
        durationMs: (endedAt ?? Date.now()) - startedAt,
      });
    };

    // Byte counting for the audit log. These listeners are safe alongside
    // pipe(): pipe() drives flow itself and calls src.pause() when the
    // destination applies backpressure, which suspends delivery to *all*
    // 'data' listeners including these. So counting here observes the pumped
    // bytes without defeating the HTTP/2 flow-control window.
    client.on('data', (chunk: Buffer) => {
      bytesUp += chunk.length;
    });
    upstream.on('data', (chunk: Buffer) => {
      bytesDown += chunk.length;
    });

    const onClientError = (): void => {
      endedAt ??= Date.now();
      upstream.destroy();
      finish();
    };
    const onUpstreamError = (): void => {
      endedAt ??= Date.now();
      client.destroy();
      finish();
    };

    client.on('error', onClientError);
    upstream.on('error', onUpstreamError);

    // Half-close propagation: when one direction ends, end the matching
    // direction upstream rather than tearing the whole connection down, so a
    // peer that is still sending can finish.
    client.pipe(upstream);
    upstream.pipe(client);

    let closedSides = 0;

    const onSideClosed = (peer: Duplex): void => {
      endedAt ??= Date.now();
      closedSides += 1;
      if (closedSides >= 2) {
        finish();
        return;
      }

      // One side is gone for good. Let the peer flush what it already has,
      // then tear it down — never wait on it indefinitely.
      peer.end();
      drainTimer = setTimeout(() => {
        peer.destroy();
        finish();
      }, PEER_DRAIN_MS);
      drainTimer.unref?.();
    };

    client.on('close', () => onSideClosed(upstream));
    upstream.on('close', () => onSideClosed(client));
  });
}
