ALTER TABLE users ADD COLUMN hanko_seed TEXT NOT NULL DEFAULT 'hanko' CHECK (length(hanko_seed) BETWEEN 1 AND 128);
ALTER TABLE users ADD COLUMN expose_preferred_username INTEGER NOT NULL DEFAULT 1 CHECK (expose_preferred_username IN (0, 1));
ALTER TABLE users ADD COLUMN expose_name INTEGER NOT NULL DEFAULT 1 CHECK (expose_name IN (0, 1));

UPDATE users SET hanko_seed = lower(hex(randomblob(16)));
