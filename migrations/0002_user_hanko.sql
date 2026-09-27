ALTER TABLE users ADD COLUMN hanko_color TEXT NOT NULL DEFAULT '#d64135';
ALTER TABLE users ADD COLUMN hanko_pattern TEXT NOT NULL DEFAULT 'fleck';

CREATE TRIGGER users_hanko_style_insert
BEFORE INSERT ON users
WHEN NEW.hanko_color NOT IN ('#d64135', '#b93028', '#5f7d63', '#805267', '#35332e')
  OR NEW.hanko_pattern NOT IN ('solid', 'fleck', 'wave', 'lattice', 'petal')
BEGIN
    SELECT RAISE(ABORT, 'invalid hanko style');
END;

CREATE TRIGGER users_hanko_style_update
BEFORE UPDATE OF hanko_color, hanko_pattern ON users
WHEN NEW.hanko_color NOT IN ('#d64135', '#b93028', '#5f7d63', '#805267', '#35332e')
  OR NEW.hanko_pattern NOT IN ('solid', 'fleck', 'wave', 'lattice', 'petal')
BEGIN
    SELECT RAISE(ABORT, 'invalid hanko style');
END;
