#!/usr/bin/env node
/**
 * Mint a connector bootstrap token.
 *
 * The token is an HMAC of the connector id under the POP's shared secret, so
 * the POP can validate a connector without a per-connector database.
 *
 *   node scripts/mint-token.mjs dc1 dev-connector-secret-change-me
 */
import { createHmac } from 'node:crypto';

const [, , connectorId, secret] = process.argv;

if (!connectorId || !secret) {
  console.error('usage: mint-token <connectorId> <connectorSecret>');
  process.exit(1);
}

console.log(createHmac('sha256', secret).update(connectorId).digest('base64url'));
