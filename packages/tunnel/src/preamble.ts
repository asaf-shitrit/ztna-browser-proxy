import type { Duplex } from 'node:stream';
import { authPreambleSchema, type AuthPreamble } from './schemas.js';

const LENGTH_BYTES = 4;
const MAX_PREAMBLE_BYTES = 8 * 1024;

/**
 * The connector authenticates itself with a length-prefixed JSON blob written
 * directly after the TLS handshake, *before* the socket becomes an HTTP/2
 * connection.
 *
 * This must read EXACTLY the preamble and not a byte more: whatever follows on
 * the wire is the HTTP/2 client preface, which belongs to the h2 session. We
 * therefore read in paused mode and `unshift()` any overshoot back onto the
 * stream so h2 receives an untouched byte sequence.
 */

export function encodePreamble(preamble: AuthPreamble): Buffer {
  const body = Buffer.from(JSON.stringify(preamble), 'utf8');
  if (body.length > MAX_PREAMBLE_BYTES) {
    throw new Error('preamble too large');
  }
  const header = Buffer.allocUnsafe(LENGTH_BYTES);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

/**
 * Write the preamble and RESOLVE ONLY ONCE IT HAS FLUSHED.
 *
 * The flush is mandatory, not a nicety. If the socket is handed to HTTP/2
 * while this write is still queued, the write's completion is delivered to the
 * Http2Session that has since taken ownership of the stream — and Node aborts
 * the process:
 *
 *   Assertion failed: is_write_in_progress()
 *   node::http2::Http2Session::OnStreamAfterWrite
 *
 * Over plain TCP the write usually drains before h2 attaches, which hides the
 * bug; over TLS it does not, and the process dies on every connect. Always
 * `await writePreamble(...)` before `serveTunnel(...)`.
 *
 * Covered by packages/tunnel/test/tls-handshake.test.ts.
 */
export function writePreamble(socket: Duplex, preamble: AuthPreamble): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(encodePreamble(preamble), (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

export async function readPreamble(
  socket: Duplex,
  timeoutMs = 10_000,
): Promise<AuthPreamble> {
  const header = await readExactly(socket, LENGTH_BYTES, timeoutMs);
  const length = header.readUInt32BE(0);
  if (length === 0 || length > MAX_PREAMBLE_BYTES) {
    throw new Error(`invalid preamble length: ${length}`);
  }
  const body = await readExactly(socket, length, timeoutMs);

  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    throw new Error('preamble is not valid JSON');
  }
  return authPreambleSchema.parse(parsed);
}

/**
 * Read exactly `n` bytes, pushing any surplus back for the next consumer.
 * Stays in paused mode throughout so we never accidentally drain the socket.
 */
function readExactly(socket: Duplex, n: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;

    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('timed out reading preamble'));
    }, timeoutMs);

    const cleanup = (): void => {
      clearTimeout(timer);
      socket.removeListener('readable', onReadable);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
    };

    const onError = (err: Error): void => {
      cleanup();
      reject(err);
    };

    const onEnd = (): void => {
      cleanup();
      reject(new Error('socket ended before preamble was complete'));
    };

    const onReadable = (): void => {
      for (;;) {
        const want = n - received;
        if (want <= 0) break;

        // Ask for exactly what we still need. If the stream holds fewer bytes
        // than requested, read(size) returns null, so fall back to read().
        const chunk: Buffer | null = (socket.read(want) ?? socket.read()) as Buffer | null;
        if (chunk === null) return; // wait for the next 'readable'

        if (chunk.length > want) {
          chunks.push(chunk.subarray(0, want));
          socket.unshift(chunk.subarray(want)); // hand the rest to HTTP/2
          received = n;
        } else {
          chunks.push(chunk);
          received += chunk.length;
        }
      }

      cleanup();
      resolve(Buffer.concat(chunks, n));
    };

    socket.on('error', onError);
    socket.on('end', onEnd);
    socket.on('readable', onReadable);
    onReadable();
  });
}
