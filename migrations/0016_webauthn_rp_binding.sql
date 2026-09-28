CREATE TABLE webauthn_rp_binding (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    rp_id TEXT NOT NULL
);
