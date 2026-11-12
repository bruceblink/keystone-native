-- 权限版本用于在角色或角色权限变化后立即失效旧访问令牌。
SET @add_permission_version = (SELECT IF(COUNT(*) = 0, 'ALTER TABLE sys_user ADD COLUMN permission_version BIGINT NOT NULL DEFAULT 1 AFTER credential_version', 'SELECT 1') FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'permission_version');
PREPARE stmt FROM @add_permission_version; EXECUTE stmt; DEALLOCATE PREPARE stmt;
