ALTER TABLE authorization_requests
    ADD COLUMN force_consent INTEGER NOT NULL DEFAULT 0 CHECK (force_consent IN (0, 1));

CREATE TABLE oidc_consents (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    granted_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (user_id, client_id)
);
CREATE INDEX oidc_consents_expiry_idx ON oidc_consents(expires_at);
