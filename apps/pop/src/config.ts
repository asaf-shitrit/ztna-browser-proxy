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

export function loadConfig(): PopConfig {
  const parsed = configSchema.parse({
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
    meshPeerCns: (process.env.MESH_PEER_CNS ?? '')
      .split(',')
      .map((c) => c.trim())
      .filter(Boolean),
    authRateLimit: num(process.env.AUTH_RATE_LIMIT, 20),
    authRateWindowMs: num(process.env.AUTH_RATE_WINDOW_MS, 60_000),
    auditGroups: (process.env.AUDIT_GROUPS ?? '')
      .split(',')
      .map((g) => g.trim())
      .filter(Boolean),
    publicProxyHost: process.env.PUBLIC_PROXY_HOST ?? 'pop.ztna.test',
    publicProxyPort: num(process.env.PUBLIC_PROXY_PORT, 8443),
    devPlaintextProxy: process.env.DEV_PLAINTEXT_PROXY === '1',
  });

  const config: PopConfig = { ...parsed };

  if (parsed.certFile && parsed.keyFile) {
    config.cert = fs.readFileSync(parsed.certFile);
    config.key = fs.readFileSync(parsed.keyFile);
  } else if (!parsed.devPlaintextProxy) {
    throw new Error(
      'TLS_CERT_FILE and TLS_KEY_FILE are required unless DEV_PLAINTEXT_PROXY=1',
    );
  }

  if (parsed.meshCaFile) {
    config.meshCa = fs.readFileSync(parsed.meshCaFile);
  }

  // Multi-POP routing needs somewhere to publish ownership, an address peers
  // can reach, and a way to authenticate the hop.
  const meshRequested = Boolean(
    parsed.meshAdvertise || parsed.meshSecret || parsed.meshPeerCns.length > 0,
  );
  if (meshRequested) {
    if (!parsed.redisUrl || !parsed.meshAdvertise) {
      throw new Error('multi-POP routing needs REDIS_URL and MESH_ADVERTISE');
    }

    const hasMutualTls = Boolean(config.cert && config.meshCa && parsed.meshPeerCns.length);
    if (!hasMutualTls && !parsed.meshSecret) {
      throw new Error(
        'multi-POP routing needs MESH_PEER_CNS (with TLS_CERT_FILE and MESH_CA_FILE) ' +
          'for mutual TLS, or MESH_SECRET as a fallback',
      );
    }
    if (!hasMutualTls) {
      console.warn(
        JSON.stringify({
          level: 'warn',
          msg: 'mesh is using a shared secret; set MESH_PEER_CNS for mutual TLS',
        }),
      );
    }
  }

  return config;
}

function num(value: string | undefined, fallback: number): number {
  return value === undefined ? fallback : Number(value);
}
