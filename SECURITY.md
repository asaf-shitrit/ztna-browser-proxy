# Security

## What this project is

A working implementation of browser-based Zero Trust Network Access, built to
demonstrate the architecture end to end. It is **not audited and not hardened
for production use.** Please read the list below before deploying it anywhere
that matters.

## Known limitations

These are deliberate scope decisions, not oversights. Each would need work
before this carried real traffic.

- **The demo CA signs everything.** `infra/certs/generate.sh` issues a single
  local CA that signs the POP certificates, the mesh identities *and* the
  application certificates. The POP mesh compensates with an explicit
  `MESH_PEER_CNS` allowlist, because a CA signature alone would let anyone
  holding an application's key authenticate as a peer POP. A real deployment
  should use separate trust domains — `MESH_CA_FILE` is already its own
  setting for exactly this reason.
- **Rate limiting is per-process and in-memory.** An attacker spreading
  attempts across POP instances gets a fresh budget on each.
- **Redis is a single point of failure.** Its loss is surfaced as `503` rather
  than mistaken for bad credentials, but there is no fallback path.
- **No device posture.** Access decisions use identity and policy only; the
  extension does not attest to the state of the device it runs on.
- **No graceful drain.** A POP shutting down cuts in-flight connections
  instead of sending `GOAWAY` and letting them finish.
- **Mesh forwarding is unbounded.** There is no cap on concurrent forwarded
  streams per peer, so one POP can exhaust another's stream budget.
- **The extension declares `<all_urls>`.** This is required to answer the
  proxy's authentication challenge for policy-defined hosts; see
  `apps/extension/src/permissions.ts` for the reasoning and how to narrow it.

## Credentials in this repository

The values in `infra/` — `admin`, `alice`, `bob`,
`dev-connector-secret-change-me` — are local demo scaffolding and grant access
to nothing outside a developer's own machine. No private keys or certificates
are committed; `infra/certs/` is generated locally and git-ignored.

## Reporting a vulnerability

Open a GitHub issue for anything affecting the demo setup. For a problem you
believe is exploitable beyond it, please report it privately through GitHub's
security advisories rather than a public issue.
