# Architecture and security design

## Initial delivery boundary

Hanko is a self-hosted identity provider process with two compiled artifacts: an Axum API and a static React management/login site. SQLite is the durable system of record. Rust modules separate configuration, persistence, browser sessions, WebAuthn, OIDC, signing keys, and the HTTP adapter so future SCIM and policy/claim providers can be added without coupling them to request handlers.

The first delivery implements local user/group/client management, passkey enrollment and usernameless passkey login, an OIDC Authorization Code flow with PKCE S256 for public clients, discovery, JWKS, token and userinfo endpoints, and browser logout. It intentionally has no password auth, SAML, LDAP, reverse proxy, or workflow engine. The server trusts `PUBLIC_ORIGIN` as its externally visible HTTPS origin; deployments terminate TLS in front of it and must not let clients override forwarded host/proto headers.

## Modules

- `config`: validates the issuer origin, SQLite URL, cookie mode, and encryption key at startup.
- `db`: migrations, repositories, transactions, and cleanup of expired/consumed transient records.
- `identity`: users, groups, memberships, passkey persistence, and future identity attributes.
- `session`: opaque browser sessions, CSRF token validation, cookie policy, and logout.
- `webauthn`: a configured `webauthn-rs` RP; ceremony states are serialized to SQLite and atomically consumed when completed.
- `oidc`: authorization request validation, code creation/consumption, PKCE, token claims, discovery, JWKS, and userinfo.
- `keys`: encrypted signing-key storage, active/retiring states, public JWK projection, and rotation.
- `http`: Axum routes/extractors, request/response types, and static-site serving.
- `web`: Vite-built React + Tailwind management and sign-in UI, served as static files by Axum.

HTTP handlers remain thin. OIDC and WebAuthn services accept repository/crypto dependencies rather than reading request globals. Claim sources and authorization policy are explicit interfaces so later SCIM and policy modules can supply identity data without changing the token endpoint.

## SQLite schema

All times are Unix seconds in UTC. IDs are random UUIDs unless they are protocol secrets, in which case only SHA-256 digests are stored.

| Table | Purpose and important constraints |
| --- | --- |
| `users` | `id`, unique internal `username`, optional unique `email`, optional OIDC `name`/`preferred_username` exposure, optional admin-only `invitation_label`, one generated Hanko seed and ink color, JSON `attributes`, `is_admin`, `disabled_at`, timestamps. |
| `invitation_links` | Hashed bearer token, admin-only label, optional email recipient, optional group list, user limit and use count, expiry and revocation timestamps. A conditional update enforces limits when a link is accepted. |
| `passkeys` | User FK, globally unique WebAuthn credential ID, serialized `webauthn-rs` `Passkey`, label and timestamps. Credential IDs cannot be attached to multiple users. |
| `groups` | Unique stable name and display metadata. |
| `group_claim_mappings` | JSON-valued custom claims attached to groups. A user receives claims from their current groups only when the configured OIDC scope is requested. |
| `user_groups` | `(user_id, group_id)` membership with cascading FKs. |
| `oidc_clients` | Public/confidential type, client ID, token endpoint authentication method (`none`, `client_secret_basic`, or `client_secret_post`), required/optional PKCE policy, optional hashed secret, name, enabled flag, JSON allowed scopes and claim mappings. |
| `client_redirect_uris` | Exact URI strings, unique per client; never wildcard/prefix matched. |
| `client_post_logout_uris` | Exact optional post-logout URI allow-list. |
| `client_allowed_groups` | Empty means no group restriction; otherwise user must belong to at least one listed group. |
| `sessions` | SHA-256 session-cookie digest, user FK, CSRF-token digest, expiry, created time; raw values exist only in the browser. |
| `authorization_requests` | Short-lived pre-login authorization transaction: request ID digest, browser-binding cookie digest, client, exact redirect URI, state, optional nonce (empty when omitted), optional S256 challenge, requested scopes, expiry. |
| `webauthn_ceremonies` | Ceremony ID digest, kind, optional user, server-generated RP state JSON, optional browser binding, expiry, consumed time. State is never trusted from the browser. |
| `authorization_codes` | Code digest, user/client, exact redirect URI, scope, optional nonce (empty when omitted), optional PKCE challenge, expiry and consumed time. Unique digest and conditional atomic consume make codes single-use. |
| `refresh_tokens` | Rotating token digest, user/client, granted scopes, original authentication time, and a 30-day inactivity expiry. Client and user deletion cascade to their tokens. |
| `signing_keys` | `kid`, algorithm, encrypted PKCS#8 private bytes, public JWK JSON, state (`active`, `retiring`, `retired`), creation and retirement times. A partial unique index permits one active key. |

JSON columns are validated at API boundaries. Migrations add constraints/indexes for unique identifiers, active records, expiry scans, and all relationship FKs. A SQLite connection enables foreign keys, WAL, and a busy timeout.

## Security model

1. **WebAuthn**: use only `webauthn-rs` high-level start/finish APIs. Configure the origin from the canonical public origin and the RP ID from `WEBAUTHN_RP_ID`, defaulting to the public origin's hostname. The RP ID must be valid for that origin. Require user verification. Persist the library's opaque registration/authentication state server-side with a short expiry; completion binds ceremony ID to the same browser and consumes it once. Registration checks global credential uniqueness. Authentication updates the stored passkey returned by the library and rejects a non-increasing non-zero signature counter.
2. **Browser sessions and CSRF**: issue random opaque session and CSRF values; persist only SHA-256 digests. Set session cookie `HttpOnly; Secure; SameSite=Lax; Path=/` (Secure is mandatory in production). Mutating browser endpoints require matching `Origin`, a session-bound `X-CSRF-Token`, and JSON content type. Sign-in ceremonies additionally bind to a short-lived HttpOnly pre-auth cookie. Login rotates that pre-auth value into a fresh session.
3. **Authorization**: require `response_type=code`, `client_id`, `redirect_uri`, `scope` including `openid`, and nonempty `state`. Clients with no token endpoint authentication always require `code_challenge_method=S256` and a valid 43–128 character base64url challenge. Confidential clients follow their configured PKCE policy (`required` or `optional`); any supplied challenge must use S256. The OIDC `nonce` parameter is optional; if supplied, it must be nonempty and no longer than 512 characters. Validate client enabled, URI exact allow-list, requested scopes subset, and group policy before asking the user to authenticate. Do not redirect errors to an unvalidated URI. The browser-bound authorization request is server-side and expires quickly.
4. **Codes and tokens**: issue high-entropy random codes and store only their digest. Public clients use no token endpoint authentication and always require PKCE S256. Confidential clients authenticate with their registered `client_secret_basic` or `client_secret_post` method and follow their configured PKCE policy. The token endpoint requires POST form encoding, exact redirect URI, the configured client authentication, a valid verifier whenever the code has a challenge, and an unexpired unused code. Consume code in one conditional database mutation before signing tokens. Sign ID and access JWTs with an active ES256 key and include `kid`; access tokens are audience/client bound and short-lived. ID tokens include the saved nonce when one was supplied. Clients granted `offline_access` receive an opaque refresh token; store only its digest and rotate it on every successful refresh grant. Refresh tokens expire after 30 days without use and are checked against current client scopes and user access policy. JWKS publishes active and retiring public keys until their last possible token expires.
5. **Key at rest/rotation**: encrypt private PKCS#8 bytes with XChaCha20-Poly1305 using a 256-bit operator-provided master key (`IDENTITY_MASTER_KEY`); include `kid` as associated data. Never silently create a default master key. Generate a new active key transactionally; mark the prior key retiring and publish it until all issued tokens can expire, then retire/remove it. Backups must include both SQLite and the master key.
6. **Deployment**: issuer/origin is fixed by configuration, HTTPS is required outside explicit local development, request body sizes are bounded, security headers are set, and untrusted forwarded headers are ignored. Secrets and token values are never logged.

## Endpoint flows

### Sign in and passkey enrollment

1. `POST /api/passkeys/login/options` creates a pre-auth cookie plus `webauthn_ceremonies` row containing the `PasskeyAuthentication` state and user binding. It returns only usernameless WebAuthn request options and an opaque ceremony ID.
2. `POST /api/passkeys/login/verify` checks Origin and browser binding, loads and atomically consumes the unexpired authentication state, calls `finish_passkey_authentication`, updates the passkey, and issues a fresh session/CSRF pair. A pending authorization request is resumed only when its pre-auth browser binding matches.
3. Authenticated `POST /api/passkeys/register/options` creates a ceremony bound to the session user and returns creation options. `POST /api/passkeys/register/verify` consumes the state, calls `finish_passkey_registration`, checks credential uniqueness, stores the returned `Passkey`, and promotes a setup-only bootstrap/enrollment session only after successful registration.

### First administrator and invited-user setup

1. The administrator submits only the one-time bootstrap code to `POST /api/bootstrap`. The server creates an account with private internal fallback identifiers and issues a setup-only session.
2. The administrator enters optional OIDC username/name values. `PUT /api/account/profile` requires the exact configured Origin, the setup session, its CSRF cookie, and the matching `X-CSRF-Token`. Empty values keep internal identifiers private and disable those OIDC claims.
3. The account chooses its generated seal color and seed; `PUT /api/account/hanko` saves the personal Hanko.
4. The account registers a passkey through the WebAuthn registration ceremony. Only after verification does the server promote the session to a normal administrator session.
5. An administrator creates an invite link with an internal label, expiry, user limit, optional email recipient, and optional groups. Recipients complete the optional OIDC profile step; the server generates private fallback identifiers, assigns the admin-only label, and increments the link's use count when they accept it. They then save their Hanko and register a passkey. WebAuthn ceremony state remains on the server throughout both flows.

### OIDC Authorization Code + PKCE

1. `GET /authorize` validates every protocol and client policy parameter before any redirect. Store the request and redirect to the local sign-in UI with an opaque request ID; bind that request to a pre-auth browser cookie.
2. After passkey login, `GET /api/authorize/request` returns the application name, redirect, and requested scopes for the consent screen. An authenticated CSRF-protected continue action issues a high entropy code, stores only its digest plus redirect URI, scopes, optional nonce and PKCE challenge, user, client, and expiry, then redirects to the already-validated URI with `code` and the original `state`. Denial consumes the pending request and redirects with `access_denied` and the original state.
3. `POST /token` validates the registered client authentication method and grant fields. If the code has a PKCE challenge, it checks S256 over the verifier before conditionally marking the code consumed. On success mint a signed ID token and access token. When the authorization includes `offline_access`, also issue a rotating refresh token; `grant_type=refresh_token` replaces it and returns fresh tokens.
4. `/userinfo` validates signature, issuer, expiry and audience of the bearer access token and returns only claims authorized by its scopes, client mappings, or group mappings.
5. `/.well-known/openid-configuration` advertises only implemented endpoints/algorithms and token authentication methods; `/jwks` returns active and still-valid retiring public keys.
6. `POST /logout` requires session CSRF, revokes the server-side session, and clears the cookie. OIDC RP-initiated logout may add `id_token_hint`, exact-allow-listed `post_logout_redirect_uri`, and round-tripped state; absent a valid allow-listed target it returns to the local signed-out page.

### OIDC custom claims

Client claim mappings read values from a user's JSON `attributes` with a JSON Pointer and can be gated by a client scope. Group claim mappings hold a JSON value directly and are included for users who belong to the group when the required scope is requested. The scope must also be enabled on the client, since authorization rejects scopes the client has not enabled. If one group contributes a claim, its JSON value is preserved. If multiple groups contribute the same claim, their top-level array values are flattened and deduplicated into an array. Client-specific mappings override group claims with the same name. Both kinds of custom claim appear in ID and access tokens and in the consent preview; `/userinfo` returns custom claims carried by the access token.

## Incremental implementation order

1. Add this design record, project skeleton, configuration validation, SQLite migrations, and health/discovery/JWKS routing.
2. Implement signing-key encryption/generation/JWKS and unit tests for key lifecycle and JWT validation.
3. Implement sessions, CSRF, user/group/client persistence and management endpoints.
4. Implement WebAuthn ceremony persistence/consume operations and passkey routes using `webauthn-rs`.
5. Implement authorization request validation, login continuation, code issuance, PKCE token exchange, userinfo and logout.
6. Build static React UI and end-to-end tests for security invariants and the protocol flow.

At each step run formatting, compilation and the focused tests added for that step. This is a starting design record; implementation may refine library-specific details while retaining these boundaries.
