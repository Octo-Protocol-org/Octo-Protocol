-- Optional display username, distinct from email. Null until the user sets one (that write path
-- is a separate change); unique case-insensitively so "Tosin" and "tosin" can't both be taken.
ALTER TABLE users ADD COLUMN username TEXT;
CREATE UNIQUE INDEX users_username_unique_idx ON users (lower(username));
