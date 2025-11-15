ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_oauth_id_check;

DROP INDEX IF EXISTS idx_users_twitter_id;

ALTER TABLE users
    DROP COLUMN IF EXISTS twitter_handle,
    DROP COLUMN IF EXISTS twitter_id,
    ALTER COLUMN google_id SET NOT NULL;
