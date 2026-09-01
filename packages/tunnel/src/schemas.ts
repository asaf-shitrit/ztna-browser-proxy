import { z } from 'zod';

/**
 * Shared wire contracts. POP, connector and extension all import these so the
 * three components cannot drift out of sync.
 */

/** A single private application reachable through a connector. */
export const catalogAppSchema = z.object({
  id: z.string().min(1),
  hosts: z.array(z.string().min(1)).min(1),
  ports: z.array(z.number().int().min(1).max(65535)).min(1),
  /**
   * Optional concrete address the connector dials instead of the hostname the
   * browser asked for.
   *
   * The browser's TLS handshake still targets the original hostname, so the
   * app's certificate must still match it — only the connector's dial target
   * changes. Useful when the app's DNS name is not resolvable from the
   * connector (common in dev, and in networks where the app is reached by a
   * static address rather than internal DNS).
   */
  dial: z
    .object({
      host: z.string().min(1),
      port: z.number().int().min(1).max(65535),
    })
    .optional(),
});
export type CatalogApp = z.infer<typeof catalogAppSchema>;

/** Response body of `GET /catalog` on the connector's h2 server. */
export const catalogSchema = z.object({
  connectorId: z.string().min(1),
  apps: z.array(catalogAppSchema),
});
export type Catalog = z.infer<typeof catalogSchema>;

/**
 * Sent by the connector immediately after the TLS handshake, before the socket
 * is handed to HTTP/2. Length-prefixed JSON — see `preamble.ts`.
 */
export const authPreambleSchema = z.object({
  connectorId: z.string().min(1),
  token: z.string().min(1),
  version: z.literal(1),
});
export type AuthPreamble = z.infer<typeof authPreambleSchema>;

/** App as exposed to the extension (no connector routing details). */
export const sessionAppSchema = z.object({
  id: z.string(),
  hosts: z.array(z.string()),
  ports: z.array(z.number()),
});

/** Response body of `POST /api/session` on the POP control API. */
export const sessionResponseSchema = z.object({
  proxyUser: z.string(),
  proxySecret: z.string(),
  expiresAt: z.number(),
  identity: z.object({
    sub: z.string(),
    email: z.string().optional(),
    name: z.string().optional(),
    groups: z.array(z.string()),
  }),
  apps: z.array(sessionAppSchema),
  proxy: z.object({
    host: z.string(),
    port: z.number(),
  }),
});
export type SessionResponse = z.infer<typeof sessionResponseSchema>;
