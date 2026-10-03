CREATE TABLE user_claim_included_groups (
    user_id TEXT NOT NULL,
    claim_name TEXT NOT NULL,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE RESTRICT,
    PRIMARY KEY (user_id, claim_name, group_id),
    FOREIGN KEY (user_id, claim_name)
        REFERENCES user_claim_mappings(user_id, claim_name) ON DELETE CASCADE
);

CREATE INDEX user_claim_included_groups_group_idx
    ON user_claim_included_groups(group_id);
