ALTER TABLE oidc_clients
ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none'
CHECK (token_endpoint_auth_method IN ('none', 'client_secret_post'));

UPDATE oidc_clients
SET token_endpoint_auth_method = CASE
    WHEN client_type = 'confidential' THEN 'client_secret_post'
    ELSE 'none'
END;

CREATE TABLE authorization_requests_new (
    request_hash BLOB PRIMARY KEY NOT NULL,
    browser_hash BLOB NOT NULL,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    state TEXT NOT NULL,
    nonce TEXT NOT NULL,
    code_challenge TEXT,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
INSERT INTO authorization_requests_new
    (request_hash, browser_hash, client_id, redirect_uri, state, nonce, code_challenge, scopes, created_at, expires_at)
SELECT request_hash, browser_hash, client_id, redirect_uri, state, nonce, code_challenge, scopes, created_at, expires_at
FROM authorization_requests;
DROP TABLE authorization_requests;
ALTER TABLE authorization_requests_new RENAME TO authorization_requests;
CREATE INDEX authorization_requests_expiry_idx ON authorization_requests(expires_at);

CREATE TABLE authorization_codes_new (
    code_hash BLOB PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL CHECK (json_valid(scopes)),
    nonce TEXT NOT NULL,
    code_challenge TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    auth_time INTEGER NOT NULL,
    consumed_at INTEGER
);
INSERT INTO authorization_codes_new
    (code_hash, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, created_at, expires_at, auth_time, consumed_at)
SELECT code_hash, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, created_at, expires_at, auth_time, consumed_at
FROM authorization_codes;
DROP TABLE authorization_codes;
ALTER TABLE authorization_codes_new RENAME TO authorization_codes;
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at);
