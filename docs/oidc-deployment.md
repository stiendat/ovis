# Multi-user Ovis with Pocket ID

One Ovis process listens on loopback. It authenticates browser requests and dispatches
authorized HTTP requests, event streams, and WebSocket frames to a user-specific Bun worker
thread. The threads share the Ovis process. Each thread runs the regular bridge with its
own collector, attachment registry, settings, caches, and agent store environment. It has
no network listener of its own. The bridge can connect to only its assigned Herdr socket.

SQLite assigns one random Herdr name to each distinct OIDC issuer and subject. Both the
identity pair and the name are unique. Herdr owns the workspaces, PTYs, scrollback, and
running agents. Two devices signed in as the same person use the same Herdr session with
independent web sessions. Provisioning and reconnection happen on demand. Ovis restarts
reuse the database and reconnect to surviving Herdr daemons.

OIDC uses the authorization code flow with S256 PKCE, single-use state and nonce, and
signed ID tokens validated against the discovered issuer, client audience, expiration, and
issuer keys. Ovis keeps no provider tokens after login. The opaque web session uses a
Secure, HttpOnly, SameSite=Lax cookie and expires after 12 hours. Mutations and WebSockets
require the configured origin. Requests carry a page binding so a stale browser tab
cannot act under a newly signed-in account. Sign-out closes that browser session and
its streams. Pocket ID may still have an active sign-in.

## Shared host

Run this mode only for Pocket ID users you trust with the host OS account. Agents can access
shared files, processes, sockets, credentials, tools and network resources as that account.
The per-user home and XDG directories keep ordinary agent settings and history discovery
separate. They grant no filesystem or process protection. Users may need to sign in to
their CLI tools under their own Ovis home. Tools that use fixed host-wide directories or
daemons can still share their own state. Projects on disk and Git worktrees are shared
resources. Agent processes survive an Ovis restart when their Herdr daemon stays alive.
Recovery after a host reboot depends on what Herdr and each agent can restore.

Host administration, legacy tokens, pairing, Portal, relay, remote PCs, runtime switching,
and self-upgrades are unavailable on the OIDC listener. Web Push, outbound alert webhooks,
and host-wide credential or usage management are also unavailable there. Each Pocket ID
browser can drive its own Herdr session and choose the existing terminal observe mode.

## Pocket ID and environment

In **Administration → OIDC Clients**, use a confidential client named **Ovis Development**.
Set its launch URL to `https://dev-ovis.datbt.dev`, turn on PKCE, and register
`https://dev-ovis.datbt.dev/auth/oidc/callback` exactly. Ovis requests the `openid profile email`
scopes and keys accounts exclusively by issuer and subject. Use Pocket ID’s allowed groups
if access is limited to a subset of users. [Pocket ID client setup](https://pocket-id.org/docs/setup/connect-an-app)

Copy [the environment example](../.env.example) to
`~/.config/ovis-dev/production.env` and give it mode `0600`. Fill in the client ID and
secret from Pocket ID. Generate `SESSION_SECRET` with `openssl rand -hex 32` and keep it
stable across upgrades. Set `OVIS_STATE_DIR` to a writable, persistent absolute directory
with a short pathname. Set `OVIS_HERDR_BIN` to the absolute path of Herdr 0.9.5 or later.
Use the Rust PTY sidecar from a compatible Ovis build or make Node 18+ and the installed
`@lydell/node-pty` available for the existing fallback.

Leave `OIDC_LOOPBACK_URL` unset for HTTPS discovery and token exchange. When this host
already runs Pocket ID on a trusted loopback endpoint, it can use
`OIDC_LOOPBACK_URL=http://127.0.0.1:80` for discovery, token exchange and JWKS. The public
issuer, authorization URL, and callback stay the same. Only endpoints on the configured
issuer’s origin may be forwarded to that loopback transport.

## Installation and upgrade

1. Install Bun at `~/ovis-dev/bin/bun` for the operating-system user that runs Herdr.
   Prepare a release checkout under `~/ovis-dev/releases/<revision>`. In that checkout,
   run `bun install --frozen-lockfile` and `bun run build`.
2. Point `~/ovis-dev/current` to the built checkout. Install
   [the service unit](../deploy/oidc/ovis-dev.service) under `~/.config/systemd/user/`.
   Run `systemctl --user daemon-reload` and `systemctl --user enable --now ovis-dev.service`.
   Enable user linger with `loginctl enable-linger "$USER"` so the service starts without
   an interactive login. The unit restarts a failed Ovis process and keeps Herdr daemons
   running when Ovis stops.
3. With the existing Cloudflare tunnel, add a public hostname for `dev-ovis.datbt.dev`
   using the [ingress example](../deploy/oidc/cloudflared-ingress.yml). Route it to
   `http://127.0.0.1:7318`, preserve the public Host and HTTPS scheme, and enable WebSockets
   and HTTP-to-HTTPS redirection at the edge. The tunnel hostname must also get its DNS record.
   If using Caddy directly, add the [site block](../deploy/oidc/Caddyfile) to the existing Caddy
   config. Point DNS to that proxy and let Caddy provision TLS. Preserve existing site blocks.
   Avoid logging callback queries, cookies, and Authorization headers at the proxy.
4. Check `curl -fsS http://127.0.0.1:7318/healthz`, then try the public HTTPS URL.
   Sign in on desktop and mobile. Confirm that a second browser under the same identity
   sees the same workspace and that a second Pocket ID identity sees only its own workspace.
   Restart Ovis and confirm both workspaces remain. Check WebSocket status in the browser.

For an upgrade, build the new revision in a new release directory, repoint `current` and run
`systemctl --user restart ovis-dev.service`. Keep the prior release for rollback. Back up the
configuration and persistent state beforehand. Use SQLite’s online backup API or the SQLite
shell’s `.backup` command for `identities.sqlite`, especially while WAL is in use. Keep
Herdr’s state under the same persistent root with the corresponding user records.

For rollback, repoint `current` to the prior compatible OIDC build and restart. For a full
withdrawal, remove only this hostname’s tunnel or proxy entry and disable
`ovis-dev.service`. Preserve the state directory and the Pocket ID client if restoring later.
The existing `ovis.datbt.dev` service has its own configuration and Herdr daemon.

## Operations

- `journalctl --user -u ovis-dev.service -n 100` shows listener and worker failures.
  Herdr has a startup log under each account’s application state directory.
- A 421 response means the proxy failed to pass the configured Host and HTTPS scheme.
  A 403 on a write or upgrade means the browser’s Origin failed validation.
- If Pocket ID rejects the callback, verify its exact registered URL, PKCE, client secret,
  issuer and system clocks. Verify discovery and the JWKS path from the Ovis host.
- If a Herdr session does not start, check the configured binary, worker startup logs and
  Unix socket path length. Sign in again after fixing startup. Avoid deleting sockets or
  state while a daemon is running.
- After rotating `SESSION_SECRET`, browsers must sign in again. Identity-to-Herdr mappings
  remain stable. Revoke Pocket ID access and invalidate current Ovis sessions if immediate
  removal is required. Stopping the entire Ovis service disconnects browsers.
- Run `bun test server/oidc/oidc.contract.test.ts` for the signed-provider tests. Set
  `OVIS_OIDC_TEST_HERDR` to an actual Herdr binary and build the frontend to exercise two
  disposable named sessions and the single HTTP and WebSocket listener.
