import { loadConfig } from './config.js';
import { log } from './handlers.js';
import { runConnector, tlsConnect } from './run.js';

/**
 * The App Connector.
 *
 * Deliberately small and unprivileged: it makes no authorization decisions.
 * The POP decides who may reach what; the connector only enforces that the POP
 * cannot ask for a target outside the catalog this connector published.
 */

const config = loadConfig();
let shuttingDown = false;

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    log('info', 'shutting down');
    shuttingDown = true;
    setTimeout(() => process.exit(0), 500).unref();
  });
}

runConnector(config, {
  connect: tlsConnect,
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  shouldStop: () => shuttingDown,
  jitter: () => Math.random(),
}).catch((err: unknown) => {
  log('error', 'fatal', { error: err instanceof Error ? err.message : String(err) });
  process.exit(1);
});
