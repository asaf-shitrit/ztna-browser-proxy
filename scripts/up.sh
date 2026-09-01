#!/usr/bin/env bash
# Bring the whole demo up: certs, token, images, services.
set -euo pipefail
cd "$(dirname "$0")/.."

SECRET="${CONNECTOR_SECRET:-dev-connector-secret-change-me}"

if [ ! -f infra/certs/pop.ztna.test.pem ]; then
  echo "==> Generating certificates"
  bash infra/certs/generate.sh
fi

echo "==> Minting connector token"
CONNECTOR_TOKEN="$(node scripts/mint-token.mjs dc1 "$SECRET")"
export CONNECTOR_TOKEN

echo "==> Starting services"
cd infra
docker compose up --build "$@"
