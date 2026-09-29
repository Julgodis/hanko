<p align="center">
  <img src="web/public/hanko.svg" alt="Hanko logo" width="128">
</p>

<h1 align="center">Hanko</h1>

<p align="center">A personal, passkey-first OIDC identity provider</p>

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

Hanko records the configured WebAuthn RP ID in the database and refuses to start if it changes later. On the first start after this migration, verify `WEBAUTHN_RP_ID` is the same value used when existing passkeys were created; the database cannot infer an earlier value. Back up the SQLite database and `IDENTITY_MASTER_KEY` together.

Open `PUBLIC_ORIGIN` and use the bootstrap token to create the first administrator and register a passkey. If setup is interrupted before the first passkey is saved, reopen that page and enter the bootstrap token again. This resumes the sole unfinished administrator account and invalidates its previous setup sessions. Bootstrap is unavailable after a passkey is registered or another account exists. For development, the defaults use `http://localhost:3000`; run the backend there, set `PUBLIC_ORIGIN=http://localhost:5173`, then run `npm run dev` in `web`.

## Features

- Local users, groups, invitations, passkeys, and administrator UI
- Public OIDC clients with PKCE and confidential clients with client secrets
- Exact redirect URI allow-lists, group policies, and scoped claims
- ES256 signing-key rotation and optional rotating refresh tokens
- OIDC discovery, JWKS, authorization, token, userinfo, and logout endpoints

Public clients must use PKCE S256. Authorization requests require `openid`, a nonempty `state`, and user review before redirect. Refresh tokens expire after 30 days of inactivity. See [docs/architecture.md](docs/architecture.md) for design details.

## Passkey sign-in and access recovery

New passkeys must be discoverable. Hanko requests a resident key and confirms the browser reports `credProps.rk=true` before storing it. If your provider cannot confirm this, registration stops with an error; remove any passkey it saved during the failed attempt before trying again.

For a passkey registered by an older Hanko version that does not appear in the normal chooser, select **Passkey not listed? Use account name** on the sign-in page. Enter the account name saved with that passkey, or the account's email if one was assigned. This sends a credential allow-list for that account so a non-discoverable key can be used. Once signed in, add a new discoverable passkey and verify that it works in a separate browser session before removing the old one. An internal account name may begin with `user-`; an administrator with access to the database can find it in the `users.username` column. Do not share a passkey export or private key to troubleshoot this.

There are currently no independent recovery codes or administrator reset flow. Keep at least two independently stored passkeys and a tested backup of the database and master key. If every passkey becomes unusable and no session remains, restoring a backup alone will not make those passkeys usable.

## Build and publish

Before every push or pull request update, run the CI checks locally:

```sh
cargo fmt --all --check
cargo check --locked
cargo test --locked
(cd web && npm ci && npm test && npm run typecheck && npm run build)
```

For a local release build, build the UI first, then the server:

```sh
cd web && npm ci && npm run build && cd ..
cargo build --release --locked
```

Build a local container from the repository root with `docker build -t hanko:local .`. The image listens on port `38013` and stores SQLite data under `/data`; mount persistent storage there. The default UI path is `/`. For a path prefix, pass `--build-arg VITE_BASE_PATH=/hanko/` to `docker build`.

You can run an older application build against a database that a newer build has migrated when the newer migrations remain backward-compatible with that application. Startup ignores migration records newer than the build's bundled migrations; it still rejects missing migrations within the bundled version range and changed checksums. Migrations are not rolled back, so use a copy of the database when testing an older build and restore the newer build afterward.

To hide fields from user profile forms in a Compose build, set `VITE_HIDDEN_USER_CLAIMS` in `.env` and pass it as a build argument:

```yaml
services:
  hanko:
    build:
      context: .
      args:
        VITE_HIDDEN_USER_CLAIMS: ${VITE_HIDDEN_USER_CLAIMS:-}
    environment:
      REQUIRED_USER_CLAIMS: ${REQUIRED_USER_CLAIMS:-}
```

Use comma-separated claim names such as `given_name,family_name,address,phone_number`. This setting only hides form fields; it does not enforce permissions in the API or revoke values already stored. Application roles cannot be edited through the self-service profile API. Provisioned `app_roles` values remain available in OIDC claims; use admin-managed groups and group claims to manage authorization roles in Hanko.

To require profile fields during account setup and profile updates, set the runtime variable `REQUIRED_USER_CLAIMS`. For example, `REQUIRED_USER_CLAIMS=preferred_username` requires users to choose a username that is shared as the OIDC `preferred_username` claim. Separate multiple fields with commas. Supported fields are defined in [`shared/user_claims.json`](shared/user_claims.json). Requiring `address` means at least one address component must be filled in. Required fields stay visible even when also listed in `VITE_HIDDEN_USER_CLAIMS`.

OIDC consent is stored per user and application. Grants persist until the user revokes them by default. Set `OIDC_CONSENT_LIFETIME_SECONDS` to a positive integer to expire grants after that many seconds; `0` keeps them persistent. Existing grants cover requests for the same or a subset of their scopes. Adding scopes or using `prompt=consent` asks the user again. Users review and revoke grants under **Account → Applications**, including expired consent grants. Consent expiry requires approval on a subsequent sign-in; it does not expire offline access. Revoking a grant disables its refresh tokens, while already issued access tokens remain valid until expiry.

The optional `OIDC_REVOKE_CONSENTS_ON_IDENTITY_CHANGE` and `OIDC_REVOKE_SESSIONS_ON_IDENTITY_CHANGE` settings default to `false`. When enabled, changes to the account's OIDC profile (name, exposed username, picture, phone, address, or profile claims) revoke the user's consent grants and/or sessions. Email is currently set by the invitation and cannot be changed in the self-service account page, so there is no email-change action to trigger these policies.

`WEBAUTHN_ALLOW_MULTIPLE_PASSKEYS_PER_AUTHENTICATOR` defaults to `true` and allows registering more than one passkey for the same Hanko account through one authenticator or passkey provider. Set it to `false` to send existing account credentials in WebAuthn's `excludeCredentials` list and block registration through an authenticator that already stores one of them. The passkeys page displays a warning when this restriction is enabled.

## Scope

Hanko focuses on passkey-first OIDC. It does not implement password sign-in, SAML, LDAP, or workflow automation. Recovery methods and SCIM are not implemented.
