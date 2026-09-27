PRAGMA foreign_keys = ON;

CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    display_name TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attributes)),
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    disabled_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE passkeys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    passkey_json TEXT NOT NULL CHECK (json_valid(passkey_json)),
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX passkeys_user_id_idx ON passkeys(user_id);

CREATE TABLE groups (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE user_groups (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE oidc_clients (
    client_id TEXT PRIMARY KEY NOT NULL,
    client_secret_hash TEXT,
    client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    CHECK ((client_type = 'public' AND client_secret_hash IS NULL) OR (client_type = 'confidential' AND client_secret_hash IS NOT NULL))
);

CREATE TABLE client_redirect_uris (
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    uri TEXT NOT NULL,
    PRIMARY KEY (client_id, uri)
);

CREATE TABLE client_post_logout_uris (
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    uri TEXT NOT NULL,
    PRIMARY KEY (client_id, uri)
);

CREATE TABLE client_scopes (
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE client_allowed_groups (
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, group_id)
);

CREATE TABLE client_claim_mappings (
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    claim_name TEXT NOT NULL,
    user_attribute_path TEXT NOT NULL,
    required_scope TEXT,
    PRIMARY KEY (client_id, claim_name)
);

CREATE TABLE sessions (
    session_hash BLOB PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash BLOB NOT NULL,
    setup_only INTEGER NOT NULL DEFAULT 0 CHECK (setup_only IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions(expires_at);

CREATE TABLE enrollment_invitations (
    token_hash BLOB PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE INDEX enrollment_invitations_expiry_idx ON enrollment_invitations(expires_at);

CREATE TABLE login_rate_limits (
    username_hash BLOB PRIMARY KEY NOT NULL,
    window_started_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL
);

CREATE TABLE authorization_requests (
    request_hash BLOB PRIMARY KEY NOT NULL,
    browser_hash BLOB NOT NULL,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    state TEXT NOT NULL,
    nonce TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX authorization_requests_expiry_idx ON authorization_requests(expires_at);

CREATE TABLE webauthn_ceremonies (
    ceremony_hash BLOB PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    browser_hash BLOB,
    state_json TEXT NOT NULL CHECK (json_valid(state_json)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE INDEX webauthn_ceremonies_expiry_idx ON webauthn_ceremonies(expires_at);

CREATE TABLE authorization_codes (
    code_hash BLOB PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    nonce TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    auth_time INTEGER NOT NULL,
    consumed_at INTEGER
);
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at);

CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm = 'ES256'),
    encrypted_private_key BLOB NOT NULL,
    public_jwk TEXT NOT NULL CHECK (json_valid(public_jwk)),
    status TEXT NOT NULL CHECK (status IN ('active', 'retiring', 'retired')),
    created_at INTEGER NOT NULL,
    retire_after INTEGER
);
CREATE UNIQUE INDEX one_active_signing_key_idx ON signing_keys(status) WHERE status = 'active';
