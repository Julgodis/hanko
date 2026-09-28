# Hanko

### A personal, passkey-first OIDC identity provider

Hanko is a self-hosted identity provider written in Rust, with a React admin and sign-in UI. It uses WebAuthn passkeys and supports OpenID Connect Authorization Code flow with PKCE. It is licensed under AGPL-3.0-only; see [LICENSE](LICENSE).

## Project status

> [!WARNING]
> This is an early-stage personal project with no independent security audit. It may contain security bugs or breaking changes; do not assume it is production-ready. Use it at your own risk and review, secure, operate, and back up your deployment. This project is not affiliated with, associated with, or endorsed by [teamhanko's Hanko project](https://github.com/teamhanko/hanko). See [LICENSE](LICENSE) for warranty and liability terms.

## Requirements

- Rust 1.88+ (the release builder uses Rust 1.98.1)
- Node.js 22 and npm
- HTTPS for deployment; HTTP is allowed on localhost

## Configure and run

```sh
cp .env.example .env
openssl rand -base64 32 # IDENTITY_MASTER_KEY
openssl rand -hex 32    # BOOTSTRAP_TOKEN
```

Set those generated values in `.env`. Set `PUBLIC_ORIGIN` to the public URL, including any path prefix. Set `VITE_BASE_PATH` in `web/.env.production` to the same prefix with a trailing slash (`/` for a root deployment). Build the UI and start the server:

```sh
cd web && npm ci && npm run build && cd ..
cargo run
```

Keep `IDENTITY_MASTER_KEY` stable and back it up with the SQLite database; it encrypts private signing keys. Keep the WebAuthn RP ID (defaults to the origin hostname) stable after passkeys are registered. If using a reverse proxy, set `TRUSTED_PROXY_ADDRESSES` to its exact peer IPs and prevent direct public access to the server.

Open `PUBLIC_ORIGIN` and use the bootstrap token to create the first administrator and register a passkey. For development, the defaults use `http://localhost:3000`; run the backend there, set `PUBLIC_ORIGIN=http://localhost:5173`, then run `npm run dev` in `web`.

## Features

- Local users, groups, invitations, passkeys, and administrator UI
- Public OIDC clients with PKCE and confidential clients with client secrets
- Exact redirect URI allow-lists, group policies, and scoped claims
- ES256 signing-key rotation and optional rotating refresh tokens
- OIDC discovery, JWKS, authorization, token, userinfo, and logout endpoints

Public clients must use PKCE S256. Authorization requests require `openid`, a nonempty `state`, and user review before redirect. Refresh tokens expire after 30 days of inactivity. See [docs/architecture.md](docs/architecture.md) for design details.

## Build and publish

Run the project checks:

```sh
cargo fmt --all --check
cargo test
cd web && npm test && npm run typecheck && npm run build
```

For a local release build, build the UI first, then the server:

```sh
cd web && npm ci && npm run build && cd ..
cargo build --release --locked
```

Build a local container from the repository root with `docker build -t hanko:local .`. The image listens on port `38013` and stores SQLite data under `/data`; mount persistent storage there. The default UI path is `/`. For a path prefix, pass `--build-arg VITE_BASE_PATH=/hanko/` to `docker build`.

To hide fields from user profile forms in a Compose build, set `VITE_HIDDEN_USER_CLAIMS` in `.env` and pass it as a build argument:

```yaml
services:
  hanko:
    build:
      context: .
      args:
        VITE_HIDDEN_USER_CLAIMS: ${VITE_HIDDEN_USER_CLAIMS:-}
```

Use comma-separated claim names such as `app_roles,given_name,family_name,address,phone_number`. This is a UI setting only: it hides form fields but does not enforce claim permissions in the API or revoke values already stored.

## Scope

Hanko focuses on passkey-first OIDC. It does not implement password sign-in, SAML, LDAP, or workflow automation. Recovery methods and SCIM are not implemented.
