#!/usr/bin/env bash
# Issue the certificates the demo needs.
#
# Chrome will only use an HTTPS proxy whose certificate it trusts, and the
# demo apps serve real TLS through the tunnel, so we need a CA the OS trusts.
# mkcert does that in one step; without it we fall back to a self-signed CA
# that you must trust manually.
set -euo pipefail
cd "$(dirname "$0")"

HOSTS=(pop.ztna.test pop2.ztna.test localhost wiki.internal payroll.internal)

if command -v mkcert >/dev/null 2>&1; then
  echo "==> Using mkcert"
  mkcert -install
  for host in "${HOSTS[@]}"; do
    # mkcert issues serverAuth+clientAuth by default, which the POP mesh needs.
    mkcert -client -cert-file "${host}.pem" -key-file "${host}-key.pem" "$host"
  done
  cp "$(mkcert -CAROOT)/rootCA.pem" ./ca.pem
  echo "==> Done. Chrome trusts these automatically."
else
  echo "==> mkcert not found; falling back to a self-signed CA (openssl)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout ca-key.pem -out ca.pem -subj "/CN=ZTNA Local Dev CA" 2>/dev/null

  for host in "${HOSTS[@]}"; do
    openssl req -newkey rsa:2048 -nodes -keyout "${host}-key.pem" \
      -out "${host}.csr" -subj "/CN=${host}" 2>/dev/null
    openssl x509 -req -in "${host}.csr" -CA ca.pem -CAkey ca-key.pem \
      -CAcreateserial -days 825 -out "${host}.pem" \
      -extfile <(printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth" "$host") 2>/dev/null
    rm -f "${host}.csr"
  done

  cat <<'MSG'

  ACTION REQUIRED: trust infra/certs/ca.pem, or Chrome will refuse the proxy.
    macOS: sudo security add-trusted-cert -d -r trustRoot \
             -k /Library/Keychains/System.keychain infra/certs/ca.pem
    Linux: copy to /usr/local/share/ca-certificates/ and run update-ca-certificates

  Installing mkcert instead is strongly recommended.
MSG
fi
