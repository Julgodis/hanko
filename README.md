# Hanko

Hanko is a small, self-hosted identity provider built in Rust. It uses passkeys for browser authentication and implements OpenID Connect Authorization Code flow with PKCE for public clients. The server uses Axum and SQLite; its static React + Tailwind admin and sign-in site is built into `web/dist` and served by Axum.

The initial release includes local users, passkeys, groups, OIDC clients, exact redirect URI allow-lists, allowed-group policies, scoped custom claims, ES256 signing-key rotation, and a focused OIDC client management screen. The architecture and data/security design are in [docs/architecture.md](docs/architecture.md).

## Requirements

- Rust 1.88 or newer
- Node.js and npm
- A canonical HTTPS origin for deployment (HTTP localhost is allowed for development)

## Configure and run

```sh
cp .env.example .env
```

Set `PUBLIC_ORIGIN` to the URL users and OIDC clients reach. It may include a clean path prefix, for example `https://id.example/hanko`. The WebAuthn RP ID defaults to the hostname in `PUBLIC_ORIGIN`; optionally set `WEBAUTHN_RP_ID` to that hostname or a valid parent domain. A parent-domain RP ID lets passkeys work across its subdomains, so only use one when all those subdomains are trusted. Keep the RP ID stable after users register passkeys. Generate a stable master key and a first-run bootstrap token:

```sh
openssl rand -base64 32
openssl rand -hex 32
```

Put the first value in `IDENTITY_MASTER_KEY` and the second in `BOOTSTRAP_TOKEN` in `.env`. Keep the master key with backups of the SQLite database; Hanko encrypts private signing keys with it. Do not rotate or lose the master key without first re-encrypting signing keys.

Build the static UI and start Hanko. Set `VITE_BASE_PATH` in `web/.env.production` to the same path prefix as `PUBLIC_ORIGIN` (including a trailing slash); this deployment uses `/hanko/`. The Vite dev server defaults to `/`.

```sh
cd web && npm ci && npm run build && cd ..
cargo run
```

Open the configured origin and follow the short setup sequence. The administrator enters the one-time bootstrap code, then chooses optional OIDC username/name claims, creates a personal Hanko, and registers a passkey. Invited users start at the OIDC information step and then create their Hanko and register a passkey. The username and name fields control the optional `preferred_username` and `name` claims; passkey sign-in does not use either. Each account has one generated seal design and can add multiple passkeys for devices. The bootstrap token is only accepted while the user table is empty. Set `DATABASE_URL` and `BIND_ADDRESS` to override the defaults.

Anonymous login, authorization, token-exchange, bootstrap, and invitation-consumption requests are limited by the source IP and by a global rate, with caps on outstanding WebAuthn ceremonies and authorization requests. When Hanko is behind a reverse proxy, set `TRUSTED_PROXY_ADDRESSES` to a comma-separated list of the proxy IP addresses that connect to Hanko. Hanko uses `X-Forwarded-For` only when the direct peer is on that list. Configure each trusted proxy to append the connecting address to that header, and prevent direct public access to Hanko around the proxy. Without this setting, Hanko uses the TCP peer address and ignores forwarded-address headers.

For local development, the defaults are `PUBLIC_ORIGIN=http://localhost:3000` and `BIND_ADDRESS=127.0.0.1:3000`. For the Vite dev server, change `PUBLIC_ORIGIN` to `http://localhost:5173`, keep the backend bound to port 3000, start Hanko, then run `npm run dev` from `web`. Vite proxies API requests to `http://127.0.0.1:3000` (override with `HANKO_API` if needed). The packaged deployment serves the compiled UI from the Rust process.

To inspect the admin UI without signing in or running the backend, start the Vite dev server and open `http://localhost:5173/?ui-preview=1`. This development-only preview uses in-memory sample clients, users, groups, invitations, and signing keys; writes affect only the current page session.

## OIDC clients

Sign in with an administrator passkey and open `{PUBLIC_ORIGIN}/admin/clients` to manage clients, users, groups, and signing keys. Account settings are grouped below the administration tabs; regular users can open `{PUBLIC_ORIGIN}/account` for the same Hanko and passkey settings layout. Public OIDC clients use PKCE without a secret. Confidential clients authenticate with their one-time client secret and may use PKCE as an additional protection. Configure the exact callback URL registered by the application and add only the scopes it needs. The server provides:

- `/.well-known/openid-configuration`
- `/jwks`
- `/authorize`
- `/token`
- `/userinfo`
- `/logout`

Authorization requires `response_type=code`, `scope` containing `openid`, nonempty `state`, and a `S256` challenge. The OIDC `nonce` parameter is optional. Users review an authorization request before Hanko redirects to the application.

Clients can enable the `offline_access` scope to receive a rotating refresh token. Refresh tokens are stored only as hashes, are bound to their client and user, and expire after 30 days of inactivity. Reuse of a consumed refresh token revokes its active token family.

`prompt=login` always requires a new passkey assertion. `max_age` requires one when the current session is older than the requested age. `prompt=none` returns `login_required` or `consent_required` when Hanko would need to show an interaction.

## Checks

```sh
cargo fmt --all --check
cargo test
cd web && npm run typecheck && npm run build
```

## Scope

Hanko is deliberately limited to OIDC and passkey-first local identity. It does not implement SAML, LDAP, reverse proxying, password sign-in, or a workflow engine. SCIM, recovery methods, and additional claim/policy providers can be added behind the existing identity and authorization boundaries.
