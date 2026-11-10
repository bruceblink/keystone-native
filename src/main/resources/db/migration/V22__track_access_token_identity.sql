ALTER TABLE sys_refresh_token ADD COLUMN access_token_id CHAR(36) NULL AFTER access_expires_at;
CREATE UNIQUE INDEX uq_refresh_access_token_id ON sys_refresh_token(access_token_id);
