CREATE TABLE user_claim_mappings (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    claim_name TEXT NOT NULL,
    claim_value TEXT NOT NULL CHECK (json_valid(claim_value)),
    required_scope TEXT CHECK (required_scope IS NULL OR required_scope IN ('openid', 'profile', 'email', 'address', 'phone', 'picture', 'groups', 'offline_access')),
    PRIMARY KEY (user_id, claim_name)
);
