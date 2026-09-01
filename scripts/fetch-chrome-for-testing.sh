#!/usr/bin/env bash
# Download Chrome for Testing.
#
# Chrome 137+ disabled the --load-extension switch in regular Chrome (and 152
# dropped the DisableLoadExtensionCommandLineSwitch escape hatch), so an
# unpacked extension can no longer be loaded from the command line there.
# Chrome for Testing keeps it, which is what the browser test needs.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache

ARCH="mac-arm64"
[ "$(uname -m)" = "x86_64" ] && ARCH="mac-x64"

if [ ! -d ".cache/chrome-${ARCH}" ]; then
  URL=$(curl -s https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json \
    | python3 -c "import sys,json;d=json.load(sys.stdin)['channels']['Stable']['downloads']['chrome'];print(next(x['url'] for x in d if x['platform']=='${ARCH}'))")
  echo "==> Downloading Chrome for Testing (~180MB)"
  curl -fSL -o .cache/cft.zip "$URL"
  unzip -q -o .cache/cft.zip -d .cache/
  rm -f .cache/cft.zip
  xattr -dr com.apple.quarantine ".cache/chrome-${ARCH}" 2>/dev/null || true
fi

echo "==> Chrome for Testing ready at .cache/chrome-${ARCH}"
