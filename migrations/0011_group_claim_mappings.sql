CREATE TABLE group_claim_mappings (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    claim_name TEXT NOT NULL,
    claim_value TEXT NOT NULL CHECK (json_valid(claim_value)),
    required_scope TEXT NOT NULL CHECK (required_scope IN ('openid', 'profile', 'email', 'groups', 'offline_access')),
    PRIMARY KEY (group_id, claim_name)
);
