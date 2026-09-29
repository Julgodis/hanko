-- Retain public verification material for RP logout hints after private keys
-- are pruned. These keys are never used for access tokens or published in JWKS.
CREATE TABLE retired_signing_public_keys (
    kid TEXT PRIMARY KEY NOT NULL,
    public_jwk TEXT NOT NULL CHECK (json_valid(public_jwk)),
    retired_at INTEGER NOT NULL
);
