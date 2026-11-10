ALTER TABLE sys_user ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE sys_user SET must_change_password = TRUE WHERE username = 'admin';
