ALTER TABLE oidc_clients
ADD COLUMN token_auth_method_next TEXT NOT NULL DEFAULT 'none'
CHECK (token_auth_method_next IN ('none', 'client_secret_basic', 'client_secret_post'));

UPDATE oidc_clients
SET token_auth_method_next = token_endpoint_auth_method;

ALTER TABLE oidc_clients DROP COLUMN token_endpoint_auth_method;

ALTER TABLE oidc_clients
RENAME COLUMN token_auth_method_next TO token_endpoint_auth_method;

ALTER TABLE oidc_clients
ADD COLUMN pkce_policy TEXT NOT NULL DEFAULT 'required'
CHECK (pkce_policy IN ('required', 'optional'));

UPDATE oidc_clients
SET pkce_policy = CASE
    WHEN client_type = 'confidential' THEN 'optional'
    ELSE 'required'
END;
