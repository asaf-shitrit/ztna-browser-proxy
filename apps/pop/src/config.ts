import fs from 'node:fs';
import { z } from 'zod';

const configSchema = z.object({
  proxyPort: z.number().int().default(8443),
  tunnelPort: z.number().int().default(8444),
  apiPort: z.number().int().default(8445),
  policyFile: z.string(),
  certFile: z.string().optional(),
  keyFile: z.string().optional(),
  /** Shared secret used to verify connector bootstrap tokens. */
  connectorSecret: z.string().min(8),
  /** Issuer as it appears in the token's `iss` claim — must match exactly. */
  oidcIssuer: z.string().url(),
  /**
   * Where the POP fetches signing keys.
   *
   * Deliberately separate from the issuer. The browser reaches the IdP at a
   * public URL (so tokens are issued with that `iss`), while the POP reaches it
   * over an internal network name. Deriving the JWKS URL from the issuer forces
   * those to be the same host, which they are not in any real deployment —
   * or in docker-compose, where it fails as a 401 on every session request.
   */
  oidcJwksUrl: z.string().url().optional(),
  oidcAudience: z.string().min(1),
  /**
   * Groups permitted to read /api/audit. Empty disables the endpoint.
   *
   * The audit trail names who reached which internal host, so it is more
   * sensitive than most of the traffic it describes. It is opt-in rather than
   * on-by-default precisely so it cannot be left exposed by omission.
   */
  auditGroups: z.array(z.string()).default([]),
  /** Failed proxy-auth attempts allowed per source address per window. */
  /**
   * Redis connection for shared session and audit state. Unset keeps both
   * in-process, which is correct for a single POP but loses them on restart
   * and cannot be shared with a sibling instance.
   */
  redisUrl: z.string().url().optional(),
  /** POP-to-POP forwarding for connectors held by a sibling instance. */
  meshPort: z.number().int().default(8446),
  /** How peers reach this POP's mesh listener, e.g. `pop-2.internal:8446`. */
  meshAdvertise: z.string().optional(),
  /** Pre-shared fallback; unnecessary once MESH_PEER_CNS is set. */
  meshSecret: z.string().optional(),
  meshCaFile: z.string().optional(),
  /** Certificate CNs of peer POPs permitted to forward through this one. */
  meshPeerCns: z.array(z.string()).default([]),
  authRateLimit: z.number().int().positive().default(20),
  authRateWindowMs: z.number().int().positive().default(60_000),
  /** Advertised to the extension so it can build the PAC script. */
  publicProxyHost: z.string().min(1),
  publicProxyPort: z.number().int(),
  sessionTtlMs: z.number().int().default(12 * 60 * 60 * 1000),
  /**
   * Dev escape hatch: run the proxy listener in plaintext so development can
   * proceed before certificates are trusted. Chrome requires an HTTPS proxy,
   * so this is only useful with curl.
   */
  devPlaintextProxy: z.boolean().default(false),
});

export type PopConfig = z.infer<typeof configSchema> & {
  cert?: Buffer;
  key?: Buffer;
  meshCa?: Buffer;
};

/** Split a comma-separated environment variable into trimmed, non-empty parts. */
function list(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
}

function readEnv(): unknown {
  return {
    proxyPort: num(process.env.PROXY_PORT, 8443),
    tunnelPort: num(process.env.TUNNEL_PORT, 8444),
    apiPort: num(process.env.API_PORT, 8445),
    policyFile: process.env.POLICY_FILE ?? '/etc/ztna/policy.yaml',
    certFile: process.env.TLS_CERT_FILE,
    keyFile: process.env.TLS_KEY_FILE,
    connectorSecret: process.env.CONNECTOR_SECRET,
    oidcIssuer: process.env.OIDC_ISSUER,
    oidcJwksUrl: process.env.OIDC_JWKS_URL,
    oidcAudience: process.env.OIDC_AUDIENCE ?? 'ztna-extension',
    redisUrl: process.env.REDIS_URL,
    meshPort: num(process.env.MESH_PORT, 8446),
    meshAdvertise: process.env.MESH_ADVERTISE,
    meshSecret: process.env.MESH_SECRET,
    meshCaFile: process.env.MESH_CA_FILE,
    meshPeerCns: list(process.env.MESH_PEER_CNS),
    authRateLimit: num(process.env.AUTH_RATE_LIMIT, 20),
    authRateWindowMs: num(process.env.AUTH_RATE_WINDOW_MS, 60_000),
    auditGroups: list(process.env.AUDIT_GROUPS),
    publicProxyHost: process.env.PUBLIC_PROXY_HOST ?? 'pop.ztna.test',
    publicProxyPort: num(process.env.PUBLIC_PROXY_PORT, 8443),
    devPlaintextProxy: process.env.DEV_PLAINTEXT_PROXY === '1',
  };
}

/** Load the certificate material referenced by the parsed config. */
function loadKeyMaterial(config: PopConfig): void {
  if (config.certFile && config.keyFile) {
    config.cert = fs.readFileSync(config.certFile);
    config.key = fs.readFileSync(config.keyFile);
  } else if (!config.devPlaintextProxy) {
    throw new Error('TLS_CERT_FILE and TLS_KEY_FILE are required unless DEV_PLAINTEXT_PROXY=1');
  }

  if (config.meshCaFile) {
    config.meshCa = fs.readFileSync(config.meshCaFile);
  }
}

/**
 * Multi-POP routing needs three things together: somewhere to publish
 * ownership, an address peers can reach, and a way to authenticate the hop.
 * Half-configured is rejected rather than silently degraded — a POP that
 * cannot forward looks identical to one whose connector is simply offline.
 */
function validateMesh(config: PopConfig): void {
  const requested = Boolean(
    config.meshAdvertise || config.meshSecret || config.meshPeerCns.length > 0,
  );
  if (!requested) return;

  if (!config.redisUrl || !config.meshAdvertise) {
    throw new Error('multi-POP routing needs REDIS_URL and MESH_ADVERTISE');
  }

  const hasMutualTls = Boolean(config.cert && config.meshCa && config.meshPeerCns.length);
  if (hasMutualTls) return;

  if (!config.meshSecret) {
    throw new Error(
      'multi-POP routing needs MESH_PEER_CNS (with TLS_CERT_FILE and MESH_CA_FILE) ' +
        'for mutual TLS, or MESH_SECRET as a fallback',
    );
  }

  console.warn(
    JSON.stringify({
      level: 'warn',
      msg: 'mesh is using a shared secret; set MESH_PEER_CNS for mutual TLS',
    }),
  );
}

export function loadConfig(): PopConfig {
  const config: PopConfig = { ...configSchema.parse(readEnv()) };
  loadKeyMaterial(config);
  validateMesh(config);
  return config;
}

function num(value: string | undefined, fallback: number): number {
  return value === undefined ? fallback : Number(value);
}
