CREATE TABLE client_users (
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, user_id)
);

CREATE INDEX client_users_user_id_idx ON client_users(user_id);

INSERT OR IGNORE INTO client_users (client_id, user_id)
SELECT DISTINCT client_id, user_id
FROM authorization_codes
WHERE consumed_at IS NOT NULL;
