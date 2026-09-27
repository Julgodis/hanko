ALTER TABLE users ADD COLUMN invitation_label TEXT;

CREATE TABLE invitation_links (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
    email TEXT,
    group_names TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(group_names)),
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX invitation_links_expiry_idx ON invitation_links(expires_at);
