CREATE TABLE refresh_tokens (
    token_hash BLOB PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    auth_time INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens(expires_at);
