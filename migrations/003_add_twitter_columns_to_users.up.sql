ALTER TABLE users
    ALTER COLUMN google_id DROP NOT NULL,
    ADD COLUMN twitter_id VARCHAR(255) UNIQUE,
    ADD COLUMN twitter_handle VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_users_twitter_id ON users(twitter_id);

ALTER TABLE users
    ADD CONSTRAINT users_oauth_id_check CHECK (google_id IS NOT NULL OR twitter_id IS NOT NULL);
