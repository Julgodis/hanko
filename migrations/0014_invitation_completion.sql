ALTER TABLE invitation_links
    ADD COLUMN pending_count INTEGER NOT NULL DEFAULT 0 CHECK (pending_count >= 0);

ALTER TABLE users
    ADD COLUMN invitation_link_id TEXT REFERENCES invitation_links(id) ON DELETE SET NULL;
ALTER TABLE users
    ADD COLUMN invitation_reserved_until INTEGER;

CREATE INDEX users_invitation_reservation_idx
    ON users(invitation_link_id, invitation_reserved_until);
