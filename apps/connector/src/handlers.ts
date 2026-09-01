import net from 'node:net';
import { once } from 'node:events';
import type { ServerHttp2Stream } from 'node:http2';
import { forwardDuplex, type CatalogApp, type ServeTunnelOptions } from '@ztna/tunnel';
import type { ConnectorConfig } from './config.js';

export function log(level: 'info' | 'warn' | 'error', msg: string, extra: object = {}): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra }));
}

/**
 * The connector's side of the tunnel. Extracted from the dial loop so the
 * integration test drives the real handlers rather than a reimplementation.
 */
export function createHandlers(config: ConnectorConfig): ServeTunnelOptions {
  return {
    control: {
      'GET /catalog': (stream) => {
        stream.respond({ ':status': 200, 'content-type': 'application/json' });
        stream.end(JSON.stringify({ connectorId: config.connectorId, apps: config.apps }));
      },
      'GET /healthz': (stream) => {
        stream.respond({ ':status': 200 });
        stream.end('ok');
      },
    },
    onConnect: (stream, target) => handleConnect(stream, target, config),
    onError: (err) => log('warn', 'tunnel error', { error: err.message }),
  };
}

export async function handleConnect(
  stream: ServerHttp2Stream,
  target: { host: string; port: number },
  config: ConnectorConfig,
): Promise<void> {
  // Defense in depth: even a fully compromised POP cannot use this connector
  // to pivot to arbitrary hosts inside the private network. The connector only
  // ever dials what it itself advertised.
  const app = findApp(config.apps, target);
  if (!app) {
    log('warn', 'refused out-of-catalog target', target);
    stream.respond({ ':status': 403 });
    stream.end();
    return;
  }

  // The authorization check above is always against what the browser asked
  // for. Only the dial target may be rewritten, and only to an address this
  // connector declared for that same app.
  const dial = app.dial ?? target;

  const upstream = net.connect({ host: dial.host, port: dial.port });
  upstream.setNoDelay(true);
  upstream.setTimeout(config.idleTimeoutMs, () => upstream.destroy());

  const connectTimer = setTimeout(() => {
    upstream.destroy(new Error('connect timeout'));
  }, config.connectTimeoutMs);

  try {
    await once(upstream, 'connect');
  } catch (err) {
    clearTimeout(connectTimer);
    const code = (err as NodeJS.ErrnoException).code;
    // 504 for a timeout, 502 for refused/unreachable — mirrors what a proxy
    // would report, so the POP can pass a meaningful status to the browser.
    stream.respond({ ':status': code === 'ETIMEDOUT' ? 504 : 502 });
    stream.end();
    log('warn', 'upstream connect failed', { ...target, error: (err as Error).message });
    return;
  }
  clearTimeout(connectTimer);

  stream.respond({ ':status': 200 });

  const { bytesUp, bytesDown } = await forwardDuplex(stream, upstream);
  log('info', 'stream closed', { ...target, bytesUp, bytesDown });
}

/** The app this target belongs to, or undefined if the connector never declared it. */
export function findApp(
  apps: CatalogApp[],
  target: { host: string; port: number },
): CatalogApp | undefined {
  const host = target.host.toLowerCase();
  return apps.find(
    (app) => app.ports.includes(target.port) && app.hosts.some((h) => h.toLowerCase() === host),
  );
}

export function isInCatalog(
  apps: CatalogApp[],
  target: { host: string; port: number },
): boolean {
  return findApp(apps, target) !== undefined;
}
