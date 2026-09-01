# ztna-browser-proxy

A browser-based Zero Trust Network Access (ZTNA) system in TypeScript: private
applications are never exposed to the internet, their DNS names never resolve
publicly, and every single connection is authorized against identity before it
is allowed to exist.

Three components:

| Component | Role |
|---|---|
| **Browser extension** (Chromium MV3) | Authenticates the user, then steers traffic for protected hostnames to the POP via a PAC script. |
| **POP** | Internet-facing broker. Terminates the browser's proxy connection, authenticates and authorizes each connection, forwards approved streams into the right tunnel. |
| **App Connector** | Runs inside the private network. Dials *out* to the POP and serves streams back through that connection. Nothing inbound is ever opened. |

```
┌──────────────┐   1. OIDC PKCE     ┌──────────┐
│  Extension   │ ─────────────────► │ Keycloak │
│  (MV3, SW)   │ ◄───── JWT ─────── └──────────┘
└──────┬───────┘
       │ 2. POST /api/session  →  { apps[], proxyUser, proxySecret }
       │ 3. chrome.proxy.settings.set(PAC)
       │ 4. CONNECT wiki.internal:443
       │    Proxy-Authorization: Basic <proxyUser:proxySecret>
       ▼
┌─────────────────────────────────────────┐         ┌──────────────┐
│                  POP                    │◄─ TLS ──│  Connector   │
│  proxy · policy · sessions · audit      │  + h2   │  (dials out) │
└─────────────────────────────────────────┘         └──────┬───────┘
                                                           │ TCP
                                                    ┌──────▼───────┐
                                                    │  wiki.internal│
                                                    └───────────────┘
```

## Quick start

Two ways to run the stack. **Native is the fastest path and needs no Docker.**

### Native (no Docker)

```bash
pnpm install
pnpm certs                      # issue certs (uses mkcert if installed — preferred)
bash scripts/fetch-keycloak.sh  # one-time, ~140MB
pnpm dev                        # starts Keycloak, POP, connector, demo apps
```

In a second terminal:

```bash
pnpm verify                     # 17 end-to-end checks against the live stack
pnpm fetch-chrome               # one-time, ~180MB
pnpm test:browser               # 15 checks driving the real extension in Chrome
```

Native mode serves the POP as `localhost`, and the connector reaches the demo
apps through a `dial` override in the catalog — so **no `/etc/hosts` edit is
needed**. The browser still speaks TLS to `wiki.internal` and still validates a
certificate issued for that name.

### Docker

```bash
pnpm install
pnpm certs
pnpm build
pnpm up             # mints the connector token, then docker compose up --build
```

Reaching the POP from the host needs `pop.ztna.test` to resolve — either add it
to `/etc/hosts` pointing at `127.0.0.1`, or use `curl --resolve
pop.ztna.test:8443:127.0.0.1`.

**Issuer vs. JWKS URL.** The browser reaches Keycloak at `localhost:8080` while
the POP reaches it at `keycloak:8080`. Tokens carry the browser-facing URL in
`iss`, so the POP validates against that (`OIDC_ISSUER`) but fetches signing
keys over the internal name (`OIDC_JWKS_URL`). Deriving one from the other
makes every session request fail with 401. Keycloak is pinned with
`KC_HOSTNAME` so the issuer stays stable regardless of which name reached it.

Then load the extension: `chrome://extensions` → enable **Developer mode** →
**Load unpacked** → select `apps/extension/dist`.

`pnpm test:browser` does the same thing unattended — it launches Chrome with
the extension, signs in as alice, and asserts the whole flow. See
**Browser testing** below for why it needs Chrome for Testing.

Sign in as **alice / alice** (group `employees`) or **bob / bob** (group
`finance`).

> **Certificate trust is the one manual step.** Chrome only uses an HTTPS proxy
> whose certificate it trusts. `mkcert` handles this automatically; the openssl
> fallback prints instructions for trusting `infra/certs/ca.pem` by hand.

## What the demo proves

1. **The apps are genuinely private.** `curl https://wiki.internal` from your
   host fails — the demo apps publish no ports and sit on an `internal: true`
   Docker network. Only the connector bridges to them.
2. **Access is identity-driven, not network-driven.** `alice` reaches the wiki
   and is refused payroll; `bob` gets the reverse. Both apps sit on the same
   network segment behind the same connector — network position grants nothing.
3. **The POP never sees app plaintext.** The demo apps serve real TLS, so the
   browser's handshake terminates at the app. The POP only ever brokers an
   opaque `CONNECT` stream.
4. **Revocation is server-side.** Signing out revokes the session at the POP,
   because Chrome caches proxy credentials and cannot be made to forget them.

### Walkthrough

| Step | Expected |
|---|---|
| `curl -sv https://wiki.internal` from the host | fails to resolve — baseline |
| Sign in as `alice` | popup lists **wiki** only |
| Visit `https://wiki.internal` | loads; audit shows `effect=allow appId=wiki` |
| Visit `https://payroll.internal` | `403`; audit shows `reason=no-matching-rule` |
| Sign in as `bob` | payroll loads, wiki denied |
| Sign out | PAC reverts to `DIRECT`; a replayed secret gets `407` |
| `docker compose stop connector` | `502` immediately, not a hung tab |

Watch decisions live:

```bash
docker compose -f infra/docker-compose.yml logs -f pop | grep '"event":"access"'
```

The audit log is also served at `GET /api/audit`, but it is **group-gated and
off by default**: it names who reached which internal host, so reading it
requires a bearer token whose groups intersect `AUDIT_GROUPS` (unset disables
the endpoint entirely). `alice` is in `ztna-admins` in the demo realm.
`/api/health` returns bare liveness to anonymous callers and the connector
inventory only to authenticated ones, and CORS is restricted to
`chrome-extension://` origins rather than `*`.

## Browser testing

`pnpm test:browser` drives the real extension in a real browser over the
DevTools Protocol: OIDC PKCE against Keycloak, the PAC install, `onAuthRequired`
answering the POP's 407, a tunnelled page load, a policy denial, untunnelled
browsing, and sign-out reverting the proxy. None of that is reachable from unit
tests.

Two constraints shape how it works:

- **It uses Chrome for Testing, not your installed Chrome.** Chrome 137
  disabled the `--load-extension` switch and Chrome 152 removed the
  `DisableLoadExtensionCommandLineSwitch` escape hatch, so regular Chrome now
  ignores the flag *silently* — the extension simply never loads, and the only
  service workers present are Chrome's own component extensions (which are
  also named `background.js`, so matching by filename finds the wrong one).
- **The extension id is pinned** by a `key` in `manifest.json`. The OIDC
  redirect URI is `https://<extension-id>.chromiumapp.org/`, and **Keycloak
  cannot wildcard a hostname** — only a trailing path — so
  `https://*.chromiumapp.org/*` never matches and the authorization request
  fails with `Invalid parameter: redirect_uri`. The exact URI is registered on
  the client in `infra/keycloak/realm-export.json`; changing the manifest key
  means changing that URI too.

## Design notes

### The tunnel is stock HTTP/2, with the roles inverted

The connector must dial outbound (it has no public address), but the POP is the
side that needs to open streams — and in HTTP/2 only the *client* may open a
stream. Rather than hand-roll a multiplexer, we separate the two roles:

```
TLS role:  connector = client,  POP = server
h2  role:  connector = SERVER,  POP = CLIENT
```

The seam is `http2.createServer()` — the plaintext h2 server — fed an
already-decrypted TLS socket via `server.emit('connection', socket)`. This buys
multiplexing, per-stream flow control, `PING` keepalive, `GOAWAY` drain, and
`CONNECT` as a first-class tunnel primitive, all from the standard library.

See the comment block at the top of [`packages/tunnel/src/serve.ts`](packages/tunnel/src/serve.ts)
before changing anything there.

### The browser leg is HTTP/1.1 on purpose

Chrome supports HTTP/2 proxies, and h2 would give nicer connection reuse. We
advertise `http/1.1` only, because:

- **ALPN is the client's choice.** Advertising both means maintaining two proxy
  code paths, not one — the opposite of a simplification.
- **Head-of-line blocking.** Over h2 every tunnelled app shares one TCP
  connection, so a single lost packet stalls all of them. Over HTTP/1.1 each
  `CONNECT` is its own connection. On the hotel-Wi-Fi links ZTNA clients
  actually run on, that difference is the whole ballgame. (This is why the
  industry moved the client leg to QUIC/MASQUE, not to h2.)

The forwarding core (`forwardToApp`) is transport-agnostic, so adding an h2
client leg later is a thin adapter rather than a rewrite.

### An opaque proxy secret, not the JWT

Chrome caches proxy credentials for the browser session and offers no API to
clear them. Using a rotating JWT as the proxy password would strand the browser
with a stale credential on every refresh. The POP instead mints a stable,
revocable secret that resolves server-side to the live identity — which also
keeps the bearer token out of the proxy path entirely.

### Defense in depth at the connector

The connector re-checks every `CONNECT` target against the catalog it published.
A fully compromised POP still cannot use a connector to pivot to arbitrary hosts
inside the private network.

## Layout

```
packages/tunnel     h2 role inversion, CONNECT plumbing, shared wire types
packages/policy     policy schema + evaluation (pure, default-deny)
apps/pop            proxy listener · tunnel listener · control API
apps/connector      dial-out agent for the private network
apps/extension      Chromium MV3 extension
apps/demo-app       stand-in private application
infra/              docker-compose, Keycloak realm, policy, certs
```

## Development

```bash
pnpm test        # 67 tests: tunnel, policy, PAC, connector catalog, POP integration
pnpm typecheck   # strict, project references
pnpm build
pnpm dev         # run the whole stack natively
pnpm verify      # end-to-end checks against a running stack
```

The test suite covers the parts most likely to break silently: the role
inversion over a real socket pair, HTTP/2 flow control actually stalling a fast
producer, `GOAWAY` draining in-flight streams, default-deny and wildcard
boundaries in the policy engine, the generated PAC script (executed, not
string-matched), and a full POP↔connector integration path including proxy auth,
policy denial, byte accounting and connector-outage behavior. Both proxy modes
are covered: HTTPS apps via `CONNECT`, and plain-HTTP apps via absolute-form
requests (path/query preservation, request bodies, and no credential leakage to
the origin).

Three of those tests exist because the corresponding bug shipped and had to be
found the hard way — each is worth reading before touching the tunnel:

- **`tls-handshake.test.ts`** — the plain-TCP tests all passed while the real
  stack failed. Over TLS, `socket.alpnProtocol` is `false` rather than
  `undefined` when no ALPN is negotiated, and Node's HTTP/2 server rejects the
  connection outright. Both ends must agree on `h2`.
- **`tls-handshake.test.ts`** also pins the preamble flush. Handing HTTP/2 a
  socket with a queued write makes Node deliver that write's completion to the
  new session and abort the process on an internal assertion.
- **`forward.test.ts`** — a keep-alive origin never closes, so waiting for both
  sides to close leaked the tunnel stream and silently dropped the audit record
  for every *successful* access. Denials were logged; successes were not.

## Operational notes

**Multi-POP.** Clients and connectors each attach to whichever POP is closest
— for clients that is just DNS pointing at the nearest `PUBLIC_PROXY_HOST`, and
it works because sessions are shared in Redis, so any POP accepts any proxy
secret. Connectors are different: a connector holds one HTTP/2 session to one
POP, and only that instance can open streams into its network. Each POP
therefore publishes the connectors it holds as a TTL lease in Redis
(`ztna:owner:<id>`), and a POP that receives a request for a connector it does
not hold forwards the stream to the POP that does, over a mutually
authenticated HTTP/2 mesh (`MESH_ADVERTISE`, `MESH_CA_FILE`, `MESH_PEER_CNS`).

Peers authenticate with client certificates, and a CA signature alone is
deliberately **not** accepted: the same CA also signs the application
certificates, so `MESH_PEER_CNS` is what makes a certificate mean "this
specific POP" rather than "something this CA signed". Each POP presents its own
certificate, so one instance can be revoked without touching the fleet.
`MESH_SECRET` remains as a fallback for deployments without a CA, and the POP
logs a warning when it is used.

The local registry is checked **first**, so the common case — the connector is
right here — pays no Redis round trip at all. A peer only ever serves from its
own registry and never forwards onward, so two POPs cannot bounce a stream
between them. Leases expire on their own, so a POP that dies needs no cleanup:
the connector reconnects elsewhere and republishes. The client's TLS still
terminates at the app, so the extra hop carries ciphertext.

`infra/docker-compose.yml` runs two POPs to exercise this: the connector
attaches to `pop`, and a client on `pop2` (port 8453) still reaches
`wiki.internal`.

**Shared state.** Set `REDIS_URL` and the POP keeps sessions and the audit
trail in Redis: a restart no longer signs everyone out, and a second POP behind
a load balancer accepts the same proxy secrets. Without it both stay
in-process, which is correct for a single instance but loses them on restart.
The audit trail is always written to stdout as well, so it survives Redis being
unavailable.

**Brute force.** Failed proxy authentication is throttled per source address
(`AUTH_RATE_LIMIT`, `AUTH_RATE_WINDOW_MS`), and a success clears the counter so
a user who mistypes once is never throttled. The key is the TCP source address,
never a header — `X-Forwarded-For` is attacker-controlled and would let one
client evade the limit or lock out another.

**Reading the audit trail.** Full access is limited to `AUDIT_GROUPS`; any
authenticated user can read their own records (`scope: "self"`), which makes
the log a transparency feature rather than an admin-only one.

**Policy reload.** `SIGHUP` reloads `policy.yaml` without dropping live tunnels
or sessions. A policy that fails to parse leaves the previous one in force
rather than failing open or denying everything.

**Forking.** `apps/extension/public/manifest.json` carries a `key`, which pins
the extension ID so the OIDC redirect URI stays stable (Keycloak cannot
wildcard a hostname). A fork that publishes to the Chrome Web Store must
generate its own key and update the redirect URI on the Keycloak client to
match — see `scripts/browser-test.mjs` for how the ID is derived.

**The extension's `<all_urls>` permission** is required, not gratuitous:
verified empirically that without it sign-in and the PAC install still succeed
but every request to a protected host hangs with the 407 unanswered. A
deployment that knows its own app domains should narrow it in `manifest.json`.
See `apps/extension/src/permissions.ts`.

## Security

This is a demonstration of the architecture, not an audited product. See
[SECURITY.md](SECURITY.md) for the known limitations before deploying it
anywhere that matters.

## Not included

HA/stateless POP, Redis/Postgres session storage, device posture, per-app TLS
inspection, DLP, Kubernetes manifests, certificate automation. `chrome.proxy` is
Chromium-only; Firefox would need a `browser.proxy.onRequest` adapter, which is
why PAC generation is kept separable in `apps/extension/src/pac.ts`.
