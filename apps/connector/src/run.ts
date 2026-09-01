import fs from 'node:fs';
import tls from 'node:tls';
import { once } from 'node:events';
import type { Duplex } from 'node:stream';
import { serveTunnel, writePreamble, TUNNEL_ALPN } from '@ztna/tunnel';
import type { ConnectorConfig } from './config.js';
import { createHandlers, log } from './handlers.js';

/**
 * The connector's dial loop, with its transport and clock injected so the
 * reconnect path can be tested against a POP that actually goes away and
 * comes back.
 */

export const MAX_BACKOFF_MS = 30_000;
export const BASE_BACKOFF_MS = 1000;

export interface RunDeps {
  /** Establish an authenticated-at-the-transport-level connection to the POP. */
  connect(config: ConnectorConfig): Promise<Duplex>;
  sleep(ms: number): Promise<void>;
  /** Loop until this returns true. */
  shouldStop(): boolean;
  /** Injected for deterministic tests; defaults to jitter. */
  jitter(): number;
}

/**
 * Exponential backoff with jitter.
 *
 * Jitter is not decoration: when a POP restarts, every connector that was
 * attached to it reconnects at once. Without jitter they retry in lockstep and
 * keep colliding on the same ticks.
 */
export function backoffFor(attempt: number, jitter = Math.random()): number {
  const base = Math.min(BASE_BACKOFF_MS * 2 ** attempt, MAX_BACKOFF_MS);
  return Math.round(base * (0.5 + jitter));
}

/** The real transport: TLS out to the POP, then the auth preamble. */
export async function tlsConnect(config: ConnectorConfig): Promise<Duplex> {
  const socket = tls.connect({
    host: config.popHost,
    port: config.popPort,
    servername: config.popHost,
    ALPNProtocols: [TUNNEL_ALPN],
    ca: config.caFile ? [fs.readFileSync(config.caFile)] : undefined,
    rejectUnauthorized: !config.insecureSkipVerify,
  });
  await once(socket, 'secureConnect');
  return socket;
}

/** One tunnel session: connect, serve, and resolve when the socket closes. */
export async function runSession(config: ConnectorConfig, deps: RunDeps): Promise<void> {
  const socket = await deps.connect(config);

  // Must flush before HTTP/2 takes the socket — see writePreamble().
  await writePreamble(socket, {
    connectorId: config.connectorId,
    token: config.token,
    version: 1,
  });

  const tunnel = serveTunnel(socket, createHandlers(config));
  log('info', 'tunnel ready', { connectorId: config.connectorId, apps: config.apps.length });

  try {
    await once(socket, 'close');
  } finally {
    tunnel.close();
  }
  log('warn', 'tunnel closed');
}

export async function runConnector(config: ConnectorConfig, deps: RunDeps): Promise<void> {
  let attempt = 0;

  while (!deps.shouldStop()) {
    try {
      await runSession(config, deps);
      attempt = 0; // a session that actually ran resets the backoff
    } catch (err) {
      log('error', 'tunnel session failed', {
        error: err instanceof Error ? err.message : String(err),
      });
    }

    if (deps.shouldStop()) break;

    const wait = backoffFor(attempt, deps.jitter());
    attempt += 1;
    log('info', 'reconnecting', { inMs: wait });
    await deps.sleep(wait);
  }
}
