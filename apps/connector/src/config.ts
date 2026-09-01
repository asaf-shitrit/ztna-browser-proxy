import fs from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { catalogAppSchema } from '@ztna/tunnel';

const configSchema = z.object({
  connectorId: z.string().min(1),
  popHost: z.string().min(1),
  popPort: z.number().int().min(1).max(65535),
  token: z.string().min(1),
  apps: z.array(catalogAppSchema).min(1),
  caFile: z.string().optional(),
  /** Dev only. Never set this outside local testing. */
  insecureSkipVerify: z.boolean().default(false),
  connectTimeoutMs: z.number().int().positive().default(10_000),
  idleTimeoutMs: z.number().int().positive().default(300_000),
});

export type ConnectorConfig = z.infer<typeof configSchema>;

export function loadConfig(): ConnectorConfig {
  const catalogPath = process.env.CATALOG_FILE ?? '/etc/ztna/catalog.yaml';
  const raw = parseYaml(fs.readFileSync(catalogPath, 'utf8')) as { apps?: unknown };

  const config = configSchema.parse({
    connectorId: process.env.CONNECTOR_ID,
    popHost: process.env.POP_HOST,
    popPort: Number(process.env.POP_TUNNEL_PORT ?? 8444),
    token: process.env.CONNECTOR_TOKEN,
    apps: raw.apps,
    caFile: process.env.POP_CA_FILE,
    insecureSkipVerify: process.env.INSECURE_SKIP_VERIFY === '1',
  });

  if (config.insecureSkipVerify) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        msg: 'TLS verification disabled — development only, never use in production',
      }),
    );
  }

  return config;
}
