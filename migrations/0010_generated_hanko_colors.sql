DROP TRIGGER users_hanko_style_insert;
DROP TRIGGER users_hanko_style_update;

CREATE TRIGGER users_hanko_style_insert
BEFORE INSERT ON users
WHEN (NEW.hanko_color NOT GLOB '#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]'
      AND NEW.hanko_color NOT GLOB 'linear(#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f],#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])')
  OR NEW.hanko_pattern NOT IN ('solid', 'fleck', 'wave', 'lattice', 'petal')
BEGIN
    SELECT RAISE(ABORT, 'invalid hanko style');
END;

CREATE TRIGGER users_hanko_style_update
BEFORE UPDATE OF hanko_color, hanko_pattern ON users
WHEN (NEW.hanko_color NOT GLOB '#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]'
      AND NEW.hanko_color NOT GLOB 'linear(#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f],#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])')
  OR NEW.hanko_pattern NOT IN ('solid', 'fleck', 'wave', 'lattice', 'petal')
BEGIN
    SELECT RAISE(ABORT, 'invalid hanko style');
END;
