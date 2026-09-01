import http from 'node:http';
import https from 'node:https';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { Policy, Identity } from '@ztna/policy';
import type { SessionStore } from './sessions.js';
import type { ConnectorRegistry } from './registry.js';
import { AuditLog, log } from './audit.js';
import type { PopConfig } from './config.js';
import type { RateLimiter } from './rate-limit.js';

/**
 * Control API consumed by the browser extension. Separate from the proxy
 * listener because it speaks ordinary HTTPS request/response, whereas the proxy
 * port speaks proxy semantics.
 */

export interface ControlApiOptions {
  config: PopConfig;
  policy: () => Policy;
  sessions: SessionStore;
  registry: ConnectorRegistry;
  audit: AuditLog;
  /** Throttles token verification, which is unauthenticated and CPU-bound. */
  limiter?: RateLimiter;
}

export type AuditScope = 'all' | 'self' | 'none';

/**
 * How much of the audit trail an identity may read.
 *
 * `all` reveals who reached which internal host across the estate, so it is
 * limited to explicitly named groups. `self` is always safe — the records are
 * about the caller's own access and describe nothing they did not already do —
 * and giving it to every authenticated user turns the audit log into a
 * transparency feature rather than an admin-only one.
 */
export function auditScope(identity: Identity, auditGroups: string[]): AuditScope {
  if (auditGroups.length > 0 && identity.groups.some((g) => auditGroups.includes(g))) {
    return 'all';
  }
  return identity.sub ? 'self' : 'none';
}

/** Backwards-compatible check for full access. */
export function canReadAudit(identity: Identity, auditGroups: string[]): boolean {
  return auditScope(identity, auditGroups) === 'all';
}

export function visibleAuditRecords<T extends { sub?: string | undefined }>(
  identity: Identity,
  scope: AuditScope,
  records: T[],
): T[] {
  if (scope === 'all') return records;
  if (scope === 'none') return [];
  return records.filter((r) => r.sub === identity.sub);
}

/**
 * Echo back only extension origins. Returning `*` here would expose every
 * response on this API to any web page that can reach the POP.
 */
export function allowedOrigin(origin: string | undefined): string | null {
  if (!origin) return null;
  return origin.startsWith('chrome-extension://') ? origin : null;
}

/** Keys come from OIDC_JWKS_URL when set, otherwise from the issuer's host. */
export function jwksUrl(config: PopConfig): string {
  return (
    config.oidcJwksUrl ??
    `${config.oidcIssuer.replace(/\/$/, '')}/protocol/openid-connect/certs`
  );
}

export function startControlApi(options: ControlApiOptions): http.Server | https.Server {
  const { config } = options;

  const jwks = createRemoteJWKSet(new URL(jwksUrl(config)));

  const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    void route(req, res, options, jwks).catch((err: unknown) => {
      log('error', 'control api error', {
        error: err instanceof Error ? err.message : String(err),
      });
      if (!res.headersSent) json(res, 500, { error: 'internal error' });
    });
  };

  const server =
    config.cert && config.key
      ? https.createServer({ cert: config.cert, key: config.key }, handler)
      : http.createServer(handler);

  server.listen(config.apiPort, '0.0.0.0', () => {
    log('info', 'control api ready', { port: config.apiPort });
  });

  return server;
}

async function route(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: ControlApiOptions,
  jwks: ReturnType<typeof createRemoteJWKSet>,
): Promise<void> {
  // Only the extension may call this API from a browser. A wildcard origin
  // would let any page the user visits read these responses cross-origin.
  const allowed = allowedOrigin(req.headers.origin);
  if (allowed) res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'authorization, content-type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }

  const path = new URL(req.url ?? '/', 'http://pop').pathname;

  if (path === '/api/health') {
    // Liveness is public; the connector and session inventory is not — it maps
    // out the private estate for anyone who asks.
    const identity = await verifyBearer(req, options, jwks);
    if (!identity) {
      json(res, 200, { status: 'ok' });
      return;
    }
    json(res, 200, {
      status: 'ok',
      connectors: options.registry.list().map((c) => ({
        id: c.connectorId,
        apps: c.catalog.apps.map((a) => a.id),
        connectedAt: c.connectedAt,
      })),
      sessions: await options.sessions.size(),
    });
    return;
  }

  if (path === '/api/audit' && req.method === 'GET') {
    const identity = await verifyBearer(req, options, jwks);
    if (!identity) {
      json(res, 401, { error: 'invalid or missing bearer token' });
      return;
    }
    const scope = auditScope(identity, options.config.auditGroups);
    if (scope === 'none') {
      log('warn', 'audit access denied', { sub: identity.sub, groups: identity.groups });
      json(res, 403, { error: 'not authorized to read the audit log' });
      return;
    }

    const records = visibleAuditRecords(identity, scope, await options.audit.recent());
    json(res, 200, { scope, records });
    return;
  }

  if (path === '/api/session' && req.method === 'POST') {
    const key = req.socket.remoteAddress ?? 'unknown';
    const decision = options.limiter?.hit(key);
    if (decision && !decision.allowed) {
      json(res, 429, { error: 'too many requests' });
      return;
    }
    await createSession(req, res, options, jwks);
    return;
  }

  if (path === '/api/session' && req.method === 'DELETE') {
    await deleteSession(req, res, options, jwks);
    return;
  }

  json(res, 404, { error: 'not found' });
}

async function createSession(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: ControlApiOptions,
  jwks: ReturnType<typeof createRemoteJWKSet>,
): Promise<void> {
  const identity = await verifyBearer(req, options, jwks);
  if (!identity) {
    json(res, 401, { error: 'invalid or missing bearer token' });
    return;
  }

  const session = await options.sessions.create(identity, options.config.sessionTtlMs);

  // Only apps this identity is actually permitted to reach. The PAC script is
  // built from this list, so an unauthorized user never even learns that a
  // protected hostname exists.
  const apps = options.policy().appsFor(identity);

  log('info', 'session issued', {
    sub: identity.sub,
    groups: identity.groups,
    apps: apps.map((a) => a.id),
  });

  json(res, 200, {
    proxyUser: session.proxyUser,
    proxySecret: session.proxySecret,
    expiresAt: session.expiresAt,
    identity,
    apps: apps.map((a) => ({ id: a.id, hosts: a.hosts, ports: a.ports })),
    proxy: {
      host: options.config.publicProxyHost,
      port: options.config.publicProxyPort,
    },
  });
}

async function deleteSession(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  options: ControlApiOptions,
  jwks: ReturnType<typeof createRemoteJWKSet>,
): Promise<void> {
  const identity = await verifyBearer(req, options, jwks);
  if (!identity) {
    json(res, 401, { error: 'invalid or missing bearer token' });
    return;
  }

  const revoked = await options.sessions.revokeBySubject(identity.sub);
  log('info', 'session revoked', { sub: identity.sub, revoked });
  json(res, 200, { revoked });
}

async function verifyBearer(
  req: http.IncomingMessage,
  options: ControlApiOptions,
  jwks: ReturnType<typeof createRemoteJWKSet>,
): Promise<Identity | null> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;

  try {
    const { payload } = await jwtVerify(header.slice(7), jwks, {
      issuer: options.config.oidcIssuer,
      audience: options.config.oidcAudience,
    });
    return toIdentity(payload);
  } catch (err) {
    log('warn', 'jwt verification failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return null;
  }
}

/** Map IdP claims onto the identity the policy engine understands. */
export function toIdentity(payload: JWTPayload): Identity | null {
  if (!payload.sub) return null;

  const raw = payload['groups'];
  const groups = Array.isArray(raw)
    ? raw.filter((g): g is string => typeof g === 'string')
        // Keycloak emits realm groups with a leading slash.
        .map((g) => (g.startsWith('/') ? g.slice(1) : g))
    : [];

  return {
    sub: payload.sub,
    email: typeof payload['email'] === 'string' ? payload['email'] : undefined,
    name: typeof payload['name'] === 'string' ? payload['name'] : undefined,
    groups,
  };
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}
