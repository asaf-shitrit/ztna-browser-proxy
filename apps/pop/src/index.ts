import { PolicyStore } from './policy-store.js';
import type { Catalog } from '@ztna/tunnel';
import { loadConfig } from './config.js';
import { AuditLog, log } from './audit.js';
import { MemorySessionStore } from './sessions.js';
import { createRedis, RedisAuditSink, RedisSessionStore } from './redis-store.js';
import { LocalOwnership, RedisOwnership, type OwnershipRegistry } from './ownership.js';
import { MeshClient, startMeshListener } from './mesh.js';
import { ConnectorRegistry, startTunnelListener } from './registry.js';
import { startProxy } from './proxy.js';
import { RateLimiter } from './rate-limit.js';
import { startControlApi } from './control-api.js';

const config = loadConfig();

// Fail fast on a bad policy: starting with a broken document would silently
// deny everything, which looks like an outage rather than a config error.
const policies = PolicyStore.fromFile(config.policyFile);
log('info', 'policy loaded', { apps: policies.get().apps.map((a) => a.id) });

// SIGHUP reloads policy without dropping live tunnels or sessions.
process.on('SIGHUP', () => {
  const result = policies.reload();
  if (result.ok) {
    log('info', 'policy reloaded', { apps: result.apps, generation: policies.generation });
  } else {
    log('error', 'policy reload failed; keeping previous policy', { error: result.error });
  }
});

// Shared state when Redis is configured; in-process otherwise.
const redis = config.redisUrl ? createRedis(config.redisUrl) : undefined;
if (redis) {
  redis.on('error', (err) => log('warn', 'redis error', { error: err.message }));
  log('info', 'using redis for sessions and audit', { url: redactUrl(config.redisUrl!) });
} else {
  log('warn', 'no REDIS_URL: sessions and audit are in-process and lost on restart');
}

const audit = new AuditLog(redis ? new RedisAuditSink(redis) : undefined);

// Shared across both proxy paths so an attacker cannot get a fresh budget by
// switching between CONNECT and absolute-form requests.
const authLimiter = new RateLimiter({
  limit: config.authRateLimit,
  windowMs: config.authRateWindowMs,
});
const apiLimiter = new RateLimiter({
  limit: config.authRateLimit,
  windowMs: config.authRateWindowMs,
});
const sessions = redis ? new RedisSessionStore(redis) : new MemorySessionStore();
const registry = new ConnectorRegistry();

/**
 * A connector may only advertise apps that policy has assigned to it. Without
 * this check a compromised connector could claim `payroll.internal` and have
 * the POP route real user traffic to it.
 */
function validateCatalog(catalog: Catalog): string | null {
  for (const app of catalog.apps) {
    const declared = policies.get().apps.find((a) => a.id === app.id);
    if (!declared) return `app '${app.id}' is not in policy`;
    if (declared.connector !== catalog.connectorId) {
      return `app '${app.id}' is assigned to connector '${declared.connector}'`;
    }
    for (const host of app.hosts) {
      if (!declared.hosts.includes(host)) {
        return `app '${app.id}' advertises undeclared host '${host}'`;
      }
    }
  }
  return null;
}

// Multi-POP routing. Clients and connectors each attach to whichever POP is
// closest, so the POP a user lands on often is not the one holding the
// connector they need. Ownership is published in Redis; the local registry is
// still checked first, so the common case pays nothing for it.
const meshEnabled = Boolean(
  redis && config.meshAdvertise && (config.meshPeerCns.length > 0 || config.meshSecret),
);

const ownership: OwnershipRegistry =
  meshEnabled && redis
    ? new RedisOwnership(redis, config.meshAdvertise!, (err) =>
        log('warn', 'ownership publish failed', { error: err.message }),
      )
    : new LocalOwnership();

const mesh = meshEnabled
  ? new MeshClient({
      secret: config.meshSecret,
      tls: Boolean(config.cert),
      ca: config.meshCa,
      // Our own certificate is our identity to peers.
      cert: config.cert,
      key: config.key,
    })
  : undefined;

if (meshEnabled) {
  startMeshListener({
    port: config.meshPort,
    cert: config.cert,
    key: config.key,
    ca: config.meshCa,
    peerCns: config.meshPeerCns,
    secret: config.meshSecret,
    registry,
  });
  log('info', 'multi-pop routing enabled', {
    advertise: config.meshAdvertise,
    peerAuth: config.meshPeerCns.length > 0 ? 'mutual-tls' : 'shared-secret',
  });
} else {
  log('info', 'single-pop mode: every connector must attach to this instance');
}

startTunnelListener({
  port: config.tunnelPort,
  ownership,
  cert: config.cert,
  key: config.key,
  connectorSecret: config.connectorSecret,
  registry,
  validateCatalog,
});

startProxy({
  port: config.proxyPort,
  authLimiter,
  cert: config.devPlaintextProxy ? undefined : config.cert,
  key: config.devPlaintextProxy ? undefined : config.key,
  policy: () => policies.get(),
  registry,
  sessions,
  audit,
  ownership,
  mesh,
  meshAddress: config.meshAdvertise,
});

startControlApi({
  config,
  policy: () => policies.get(),
  sessions,
  registry,
  audit,
  limiter: apiLimiter,
});

if (config.devPlaintextProxy) {
  log('warn', 'proxy listener is PLAINTEXT (DEV_PLAINTEXT_PROXY=1) — curl only, not Chrome');
}

/** Never log Redis credentials. */
function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    return u.toString();
  } catch {
    return '<invalid url>';
  }
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    log('info', 'shutting down');
    for (const connector of registry.list()) connector.client.close();
    ownership.close();
    mesh?.close();
    void redis?.quit();
    setTimeout(() => process.exit(0), 300).unref();
  });
}
