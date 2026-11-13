-- 一次性迁移岗位和菜单身份。
-- 新主键使用 UUIDv7，固定系统记录使用 UUIDv5；MySQL 统一保存 BINARY(16)。
-- V46 已经删除旧用户、角色和部门数据，本迁移也清空旧岗位、菜单及其关系。

CREATE TABLE IF NOT EXISTS sys_uuid_menu_post_migration (
  migration_key VARCHAR(64) PRIMARY KEY,
  completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

SET @uuid_menu_post_should_rebuild = (SELECT IF(COUNT(*) = 0, 1, 0)
  FROM sys_uuid_menu_post_migration WHERE migration_key = 'V47_UUID_POST_MENU');

SET FOREIGN_KEY_CHECKS = 0;
SET @drop_post_menu_0 = IF(@uuid_menu_post_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_menu_permission', 'SELECT 1');
PREPARE stmt FROM @drop_post_menu_0; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_post_menu_1 = IF(@uuid_menu_post_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_role_menu', 'SELECT 1');
PREPARE stmt FROM @drop_post_menu_1; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_post_menu_2 = IF(@uuid_menu_post_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_menu', 'SELECT 1');
PREPARE stmt FROM @drop_post_menu_2; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_post_menu_3 = IF(@uuid_menu_post_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_post', 'SELECT 1');
PREPARE stmt FROM @drop_post_menu_3; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @alter_user_post = IF(@uuid_menu_post_should_rebuild = 1,
  'ALTER TABLE sys_user DROP INDEX idx_user_post, DROP COLUMN post_id, ADD COLUMN post_id BINARY(16) NULL, ADD INDEX idx_user_post (post_id)',
  'SELECT 1');
PREPARE stmt FROM @alter_user_post; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE IF NOT EXISTS sys_post (
  id BINARY(16) PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

SET @add_user_post_fk = IF(@uuid_menu_post_should_rebuild = 1,
  'ALTER TABLE sys_user ADD CONSTRAINT fk_user_post FOREIGN KEY (post_id) REFERENCES sys_post(id) ON DELETE SET NULL',
  'SELECT 1');
PREPARE stmt FROM @add_user_post_fk; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS sys_menu (
  id BINARY(16) PRIMARY KEY,
  parent_id BINARY(16) NULL,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  path VARCHAR(255) NULL,
  component VARCHAR(255) NULL,
  menu_type VARCHAR(16) NOT NULL DEFAULT 'MENU',
  permission VARCHAR(128) NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT fk_menu_parent FOREIGN KEY (parent_id) REFERENCES sys_menu(id) ON DELETE RESTRICT,
  INDEX idx_menu_parent_sort (parent_id, sort_order, id)
);

CREATE TABLE IF NOT EXISTS sys_role_menu (
  role_id BINARY(16) NOT NULL,
  menu_id BINARY(16) NOT NULL,
  PRIMARY KEY (role_id, menu_id),
  CONSTRAINT fk_role_menu_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_menu_menu FOREIGN KEY (menu_id) REFERENCES sys_menu(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sys_menu_permission (
  menu_id BINARY(16) NOT NULL,
  permission_id BINARY(16) NOT NULL,
  PRIMARY KEY (menu_id, permission_id),
  CONSTRAINT fk_menu_permission_menu FOREIGN KEY (menu_id) REFERENCES sys_menu(id) ON DELETE CASCADE,
  CONSTRAINT fk_menu_permission_permission FOREIGN KEY (permission_id) REFERENCES sys_permission(id) ON DELETE CASCADE
);

INSERT INTO sys_post (id, code, name, sort_order)
VALUES
  (UUID_TO_BIN('dcac1296-af29-57d6-8360-6fc4afd59c04', 0), 'ceo', '董事长', 1),
  (UUID_TO_BIN('05a2e6cc-17a6-5d89-8ccf-ede706317268', 0), 'se', '项目经理', 2),
  (UUID_TO_BIN('852b04a0-d567-5bc4-bc55-f311d7dd4609', 0), 'user', '普通员工', 5)
ON DUPLICATE KEY UPDATE code = code;

INSERT INTO sys_menu (id, parent_id, code, name, path, menu_type, sort_order)
VALUES
  (UUID_TO_BIN('4bdd5b54-f7cb-5a63-bcf9-a5b3ef31d6c3', 0), NULL, 'dashboard', 'Dashboard', '/dashboard', 'MENU', 0),
  (UUID_TO_BIN('0e979b62-e21f-50bb-95ae-17523f142ab8', 0), NULL, 'system', 'System Management', '/system', 'CATALOG', 10),
  (UUID_TO_BIN('d72950bf-aa61-54b1-abdb-060c336b45f5', 0), UUID_TO_BIN('0e979b62-e21f-50bb-95ae-17523f142ab8', 0), 'system:user', 'Users', '/system/users', 'MENU', 0)
ON DUPLICATE KEY UPDATE code = code;

INSERT INTO sys_menu_permission (menu_id, permission_id)
SELECT UUID_TO_BIN('d72950bf-aa61-54b1-abdb-060c336b45f5', 0), id
FROM sys_permission WHERE code = 'user:read'
ON DUPLICATE KEY UPDATE menu_id = menu_id;

INSERT INTO sys_role_menu (role_id, menu_id)
SELECT id, UUID_TO_BIN('4bdd5b54-f7cb-5a63-bcf9-a5b3ef31d6c3', 0) FROM sys_role WHERE code = 'ADMIN'
ON DUPLICATE KEY UPDATE role_id = role_id;
INSERT INTO sys_role_menu (role_id, menu_id)
SELECT id, UUID_TO_BIN('0e979b62-e21f-50bb-95ae-17523f142ab8', 0) FROM sys_role WHERE code = 'ADMIN'
ON DUPLICATE KEY UPDATE role_id = role_id;
INSERT INTO sys_role_menu (role_id, menu_id)
SELECT id, UUID_TO_BIN('d72950bf-aa61-54b1-abdb-060c336b45f5', 0) FROM sys_role WHERE code = 'ADMIN'
ON DUPLICATE KEY UPDATE role_id = role_id;

INSERT INTO sys_role_permission (role_id, permission_id)
SELECT role.id, permission.id
FROM sys_role role
JOIN sys_permission permission ON permission.code IN (
  'user:read', 'user:update', 'session:revoke', 'department:read',
  'dictionary:read', 'post:read', 'menu:read', 'file:read', 'file:write'
)
WHERE role.code = 'USER'
ON DUPLICATE KEY UPDATE role_id = role_id;

-- 读取边界使用 BIN_TO_UUID，应用层只返回规范小写字符串。
SET @uuid_menu_post_dashboard_id = (SELECT BIN_TO_UUID(id, 0) FROM sys_menu WHERE code = 'dashboard' LIMIT 1);

INSERT INTO sys_uuid_menu_post_migration (migration_key)
VALUES ('V47_UUID_POST_MENU')
ON DUPLICATE KEY UPDATE migration_key = migration_key;
