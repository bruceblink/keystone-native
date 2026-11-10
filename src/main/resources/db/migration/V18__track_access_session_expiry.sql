ALTER TABLE sys_refresh_token ADD COLUMN access_expires_at TIMESTAMP NULL AFTER expires_at;
UPDATE sys_refresh_token SET access_expires_at = CURRENT_TIMESTAMP WHERE access_expires_at IS NULL;
