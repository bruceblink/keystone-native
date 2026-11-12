SET @add_failed_count = (SELECT IF(COUNT(*) = 0, 'ALTER TABLE sys_user ADD COLUMN failed_login_count INT NOT NULL DEFAULT 0 AFTER must_change_password', 'SELECT 1') FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'failed_login_count');
PREPARE stmt FROM @add_failed_count; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @add_locked_until = (SELECT IF(COUNT(*) = 0, 'ALTER TABLE sys_user ADD COLUMN locked_until TIMESTAMP NULL AFTER failed_login_count', 'SELECT 1') FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'locked_until');
PREPARE stmt FROM @add_locked_until; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @add_credential_version = (SELECT IF(COUNT(*) = 0, 'ALTER TABLE sys_user ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 1 AFTER locked_until', 'SELECT 1') FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'credential_version');
PREPARE stmt FROM @add_credential_version; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @add_password_changed = (SELECT IF(COUNT(*) = 0, 'ALTER TABLE sys_user ADD COLUMN last_password_changed_at TIMESTAMP NULL AFTER credential_version', 'SELECT 1') FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'last_password_changed_at');
PREPARE stmt FROM @add_password_changed; EXECUTE stmt; DEALLOCATE PREPARE stmt;
