#!/usr/bin/env bash
#
# End-to-end verification against a running native stack (scripts/dev-native.sh).
# Exercises the real path: OIDC login -> POP session -> proxy CONNECT ->
# tunnel -> private app, plus the denial and revocation cases.
set -uo pipefail
cd "$(dirname "$0")/.."

CA="$PWD/infra/certs/ca.pem"
API="https://localhost:8445"
PROXY="https://localhost:8443"
ISSUER="http://localhost:8080/realms/ztna"

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf "  \033[32m✓\033[0m %-52s %s\n" "$1" "$3"; pass=$((pass+1))
  else
    printf "  \033[31m✗\033[0m %-52s expected %s, got %s\n" "$1" "$2" "$3"; fail=$((fail+1))
  fi
}

login() { # username password -> access token
  curl -s -X POST "$ISSUER/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=ztna-extension \
    -d "username=$1" -d "password=$2" -d scope=openid \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))'
}

session() { # token -> "user:secret"
  curl -s -X POST "$API/api/session" --cacert "$CA" \
    -H "authorization: Bearer $1" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["proxyUser"]+":"+d["proxySecret"])'
}

apps_for() { # token -> comma separated app ids
  curl -s -X POST "$API/api/session" --cacert "$CA" \
    -H "authorization: Bearer $1" \
    | python3 -c 'import sys,json; print(",".join(a["id"] for a in json.load(sys.stdin)["apps"]))'
}

# Status the POP returned to the CONNECT request itself.
#
# NOTE: %{http_code} is the wrong field here. When a proxy refuses a CONNECT,
# curl reports a connection error and http_code stays 000; the proxy's status
# is only exposed as %{http_connect}.
connect_status() { # creds host -> 200 | 403 | 407 | 502
  curl -s -o /dev/null -w '%{http_connect}' \
    --proxy "$PROXY" --proxy-cacert "$CA" --proxy-user "$1" \
    --cacert "$CA" --max-time 15 "https://$2/" 2>/dev/null
}

# Absolute-form request: an http:// target goes through the proxy without a
# CONNECT, so the ordinary http_code is the right field here.
http_via_proxy() { # creds url -> status
  curl -s -o /dev/null -w '%{http_code}' \
    --proxy "$PROXY" --proxy-cacert "$CA" --proxy-user "$1" \
    --max-time 15 "$2" 2>/dev/null
}

# Status the private app itself returned, once the tunnel is established.
app_status() { # creds host -> 200
  curl -s -o /dev/null -w '%{http_code}' \
    --proxy "$PROXY" --proxy-cacert "$CA" --proxy-user "$1" \
    --cacert "$CA" --max-time 15 "https://$2/" 2>/dev/null
}

echo ""
echo "ZTNA end-to-end verification"
echo "════════════════════════════════════════════════════════════════════════"

echo ""
echo "Identity"
ALICE=$(login alice alice); BOB=$(login bob bob)
check "alice authenticates against Keycloak" "yes" "$([ -n "$ALICE" ] && echo yes || echo no)"
check "bob authenticates against Keycloak"   "yes" "$([ -n "$BOB" ] && echo yes || echo no)"

echo ""
echo "Entitlements (the POP only reveals apps the identity may reach)"
check "alice sees the wiki (https + http)" "wiki,wiki-http" "$(apps_for "$ALICE")"
check "bob sees only payroll"       "payroll" "$(apps_for "$BOB")"

A_CREDS=$(session "$ALICE"); B_CREDS=$(session "$BOB")

echo ""
echo "Access through the tunnel"
check "alice -> wiki.internal      (tunnel opens)" "200" "$(connect_status "$A_CREDS" wiki.internal)"
check "alice -> wiki.internal      (app responds)" "200" "$(app_status "$A_CREDS" wiki.internal)"
check "alice -> payroll.internal   (denied)"       "403" "$(connect_status "$A_CREDS" payroll.internal)"
check "bob   -> payroll.internal   (tunnel opens)" "200" "$(connect_status "$B_CREDS" payroll.internal)"
check "bob   -> payroll.internal   (app responds)" "200" "$(app_status "$B_CREDS" payroll.internal)"
check "bob   -> wiki.internal      (denied)"       "403" "$(connect_status "$B_CREDS" wiki.internal)"

echo ""
echo "Plain HTTP through the proxy (absolute-form, no CONNECT)"
check "alice -> http://wiki.internal    (allowed)" "200" "$(http_via_proxy "$A_CREDS" http://wiki.internal/)"
check "bob   -> http://wiki.internal    (denied)"  "403" "$(http_via_proxy "$B_CREDS" http://wiki.internal/)"
check "POST with a body is forwarded"              "200" "$(curl -s -o /dev/null -w '%{http_code}' --proxy "$PROXY" --proxy-cacert "$CA" --proxy-user "$A_CREDS" --max-time 15 -X POST -d k=v http://wiki.internal/submit 2>/dev/null)"

echo ""
echo "Credentials"
check "no proxy credentials"        "407" "$(curl -s -o /dev/null -w '%{http_connect}' --proxy "$PROXY" --proxy-cacert "$CA" --cacert "$CA" --max-time 15 https://wiki.internal/ 2>/dev/null)"
check "wrong proxy secret"          "407" "$(connect_status "${A_CREDS%%:*}:wrong-secret" wiki.internal)"

echo ""
echo "Revocation (sign-out must be enforced server-side)"
curl -s -X DELETE "$API/api/session" --cacert "$CA" -H "authorization: Bearer $ALICE" >/dev/null
check "alice's secret stops working after sign-out" "407" "$(connect_status "$A_CREDS" wiki.internal)"

echo ""
echo "Isolation (the apps must be unreachable without the tunnel)"
check "wiki.internal does not resolve on the host" "000" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://wiki.internal/ 2>/dev/null)"

echo ""
echo "════════════════════════════════════════════════════════════════════════"
printf "  %d passed, %d failed\n\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
