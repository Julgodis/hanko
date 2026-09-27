CREATE TABLE refresh_token_families (
    family_id TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX refresh_token_families_expiry_idx ON refresh_token_families(expires_at);

ALTER TABLE refresh_tokens
ADD COLUMN family_id TEXT REFERENCES refresh_token_families(family_id) ON DELETE CASCADE;
ALTER TABLE refresh_tokens ADD COLUMN consumed_at INTEGER;

INSERT INTO refresh_token_families (family_id, client_id, user_id, created_at, expires_at)
SELECT lower(hex(token_hash)), client_id, user_id, created_at, expires_at
FROM refresh_tokens;
UPDATE refresh_tokens SET family_id = lower(hex(token_hash));
CREATE UNIQUE INDEX one_active_refresh_token_per_family_idx
    ON refresh_tokens(family_id)
    WHERE family_id IS NOT NULL AND consumed_at IS NULL;
CREATE TRIGGER refresh_tokens_require_family
BEFORE INSERT ON refresh_tokens
WHEN NEW.family_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM refresh_token_families
    WHERE family_id = NEW.family_id
      AND client_id = NEW.client_id
      AND user_id = NEW.user_id
)
BEGIN
    SELECT RAISE(ABORT, 'refresh token must match a token family');
END;

ALTER TABLE authorization_requests ADD COLUMN max_age INTEGER;
ALTER TABLE authorization_requests ADD COLUMN force_reauthentication INTEGER NOT NULL DEFAULT 0
    CHECK (force_reauthentication IN (0, 1));
ALTER TABLE authorization_requests ADD COLUMN prior_session_hash BLOB;
ALTER TABLE authorization_requests ADD COLUMN created_at_ms INTEGER NOT NULL DEFAULT 0;
UPDATE authorization_requests SET created_at_ms = created_at * 1000;

ALTER TABLE sessions ADD COLUMN authenticated_at_ms INTEGER NOT NULL DEFAULT 0;
UPDATE sessions SET authenticated_at_ms = created_at * 1000;

CREATE TABLE anonymous_rate_limits (
    endpoint TEXT NOT NULL,
    source_hash BLOB NOT NULL,
    window_started_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    PRIMARY KEY (endpoint, source_hash)
);
CREATE INDEX anonymous_rate_limits_window_idx
    ON anonymous_rate_limits(endpoint, window_started_at);
CREATE INDEX login_rate_limits_window_idx ON login_rate_limits(window_started_at);
