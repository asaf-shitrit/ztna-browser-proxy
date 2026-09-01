#!/usr/bin/env bash
# Download and extract Keycloak for the native runner.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${KEYCLOAK_VERSION:-26.0.7}"
mkdir -p .cache
if [ ! -d ".cache/keycloak-${VERSION}" ]; then
  echo "==> Downloading Keycloak ${VERSION} (~140MB)"
  curl -fSL -o .cache/keycloak.zip \
    "https://github.com/keycloak/keycloak/releases/download/${VERSION}/keycloak-${VERSION}.zip"
  unzip -q -o .cache/keycloak.zip -d .cache/
fi
echo "==> Keycloak ready at .cache/keycloak-${VERSION}"
