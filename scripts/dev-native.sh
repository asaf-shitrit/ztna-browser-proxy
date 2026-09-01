#!/usr/bin/env bash
#
# Run the whole ZTNA stack natively, without Docker.
#
# Ports:
#   8080  Keycloak
#   8443  POP proxy       (what the browser's PAC points at)
#   8444  POP tunnel      (connector dials in here)
#   8445  POP control API (extension calls this)
#   9443  wiki.internal   demo app
#   9444  payroll.internal demo app
#
# The demo apps listen on loopback; the connector reaches them via the `dial`
# override in infra/connector/catalog.native.yaml, so no /etc/hosts entry is
# needed. The browser still speaks TLS to wiki.internal and still validates a
# certificate issued for that name.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$PWD"
SECRET="${CONNECTOR_SECRET:-dev-connector-secret-change-me}"
KEYCLOAK_DIR="$(echo "$ROOT"/.cache/keycloak-*/ | head -1)"
LOGS="$ROOT/.cache/logs"
mkdir -p "$LOGS"

PIDS=()
cleanup() {
  echo ""
  echo "==> Shutting down"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ ! -f infra/certs/localhost.pem ]; then
  echo "==> Generating certificates"
  bash infra/certs/generate.sh
fi

echo "==> Building"
pnpm --filter @ztna/tunnel --filter @ztna/policy build >/dev/null
pnpm --filter @ztna/pop --filter @ztna/connector --filter @ztna/demo-app build >/dev/null

# ---------------------------------------------------------------- Keycloak
if [ ! -d "$KEYCLOAK_DIR" ]; then
  echo "!! Keycloak not found in .cache/. Run scripts/fetch-keycloak.sh first." >&2
  exit 1
fi

echo "==> Starting Keycloak (first run imports the realm; this takes ~30s)"
mkdir -p "$KEYCLOAK_DIR/data/import"
cp infra/keycloak/realm-export.json "$KEYCLOAK_DIR/data/import/"
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  "$KEYCLOAK_DIR/bin/kc.sh" start-dev --http-port=8080 --import-realm \
  > "$LOGS/keycloak.log" 2>&1 &
PIDS+=($!)

printf "    waiting for Keycloak"
for _ in $(seq 1 120); do
  if curl -sf http://localhost:8080/realms/ztna/.well-known/openid-configuration >/dev/null 2>&1; then
    echo " ready"
    break
  fi
  printf "."
  sleep 1
done

if ! curl -sf http://localhost:8080/realms/ztna/.well-known/openid-configuration >/dev/null 2>&1; then
  echo ""
  echo "!! Keycloak did not become ready. See $LOGS/keycloak.log" >&2
  exit 1
fi

# ---------------------------------------------------------------- demo apps
echo "==> Starting private apps"
APP_NAME="Corporate Wiki" APP_ACCENT="#3b6ea5" \
  HTTP_PORT=9080 HTTPS_PORT=9443 \
  TLS_CERT_FILE="$ROOT/infra/certs/wiki.internal.pem" \
  TLS_KEY_FILE="$ROOT/infra/certs/wiki.internal-key.pem" \
  node apps/demo-app/dist/index.js > "$LOGS/wiki.log" 2>&1 &
PIDS+=($!)

APP_NAME="Payroll" APP_ACCENT="#8b5a2b" \
  HTTP_PORT=9081 HTTPS_PORT=9444 \
  TLS_CERT_FILE="$ROOT/infra/certs/payroll.internal.pem" \
  TLS_KEY_FILE="$ROOT/infra/certs/payroll.internal-key.pem" \
  node apps/demo-app/dist/index.js > "$LOGS/payroll.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------- POP
echo "==> Starting POP"
PROXY_PORT=8443 TUNNEL_PORT=8444 API_PORT=8445 \
  POLICY_FILE="$ROOT/infra/policy.native.yaml" \
  TLS_CERT_FILE="$ROOT/infra/certs/localhost.pem" \
  TLS_KEY_FILE="$ROOT/infra/certs/localhost-key.pem" \
  CONNECTOR_SECRET="$SECRET" \
  OIDC_ISSUER=http://localhost:8080/realms/ztna \
  OIDC_AUDIENCE=ztna-extension \
  AUDIT_GROUPS=ztna-admins \
  PUBLIC_PROXY_HOST=localhost PUBLIC_PROXY_PORT=8443 \
  node apps/pop/dist/index.js 2>&1 | tee "$LOGS/pop.log" &
PIDS+=($!)

sleep 2

# ---------------------------------------------------------------- connector
echo "==> Starting connector"
CONNECTOR_ID=dc1 \
  POP_HOST=localhost POP_TUNNEL_PORT=8444 \
  CONNECTOR_TOKEN="$(node scripts/mint-token.mjs dc1 "$SECRET")" \
  CATALOG_FILE="$ROOT/infra/connector/catalog.native.yaml" \
  POP_CA_FILE="$ROOT/infra/certs/ca.pem" \
  NODE_OPTIONS="--dns-result-order=ipv4first" \
  node apps/connector/dist/index.js > "$LOGS/connector.log" 2>&1 &
PIDS+=($!)

sleep 2

cat <<INFO

────────────────────────────────────────────────────────────────
  ZTNA stack is up (native, no Docker)

  Keycloak     http://localhost:8080   (admin / admin)
  POP proxy    https://localhost:8443
  Control API  https://localhost:8445/api/health

  Users        alice / alice   (employees -> wiki)
               bob   / bob     (finance   -> payroll)

  Load the extension: chrome://extensions -> Developer mode
                      -> Load unpacked -> apps/extension/dist

  Logs         .cache/logs/*.log
  Verify       bash scripts/verify-native.sh

  Ctrl-C to stop everything.
────────────────────────────────────────────────────────────────

INFO

wait
