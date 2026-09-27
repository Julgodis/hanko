CREATE TABLE credential_change_approvals (
    approval_hash BLOB PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash BLOB NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('add', 'remove')),
    target_passkey_id TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    CHECK ((action = 'add' AND target_passkey_id IS NULL) OR
           (action = 'remove' AND target_passkey_id IS NOT NULL))
);
CREATE INDEX credential_change_approvals_expiry_idx
    ON credential_change_approvals(expires_at);

