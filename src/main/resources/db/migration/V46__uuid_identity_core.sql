-- 一次性重建身份核心表。
-- 用户、角色和部门的新 ID 由应用使用 UUIDv7 生成；固定系统记录使用 UUIDv5。
-- 本迁移允许破坏性更新，因此会清空旧数字 ID 及其关系。所有 UUID 列使用 MySQL BINARY(16)，
-- SQL 边界统一使用 UUID_TO_BIN(..., 0) 和 BIN_TO_UUID(..., 0)。

CREATE TABLE IF NOT EXISTS sys_uuid_identity_migration (
  migration_key VARCHAR(64) PRIMARY KEY,
  completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

SET @uuid_identity_should_rebuild = (SELECT IF(COUNT(*) = 0, 1, 0)
  FROM sys_uuid_identity_migration WHERE migration_key = 'V46_UUID_IDENTITY_CORE');

SET FOREIGN_KEY_CHECKS = 0;
SET @drop_0 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_auth_challenge', 'SELECT 1');
PREPARE stmt FROM @drop_0; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_1 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_user_mfa', 'SELECT 1');
PREPARE stmt FROM @drop_1; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_2 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_mfa_recovery_code', 'SELECT 1');
PREPARE stmt FROM @drop_2; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_3 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_auth_session', 'SELECT 1');
PREPARE stmt FROM @drop_3; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_4 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_refresh_token', 'SELECT 1');
PREPARE stmt FROM @drop_4; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_5 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_refresh_token_event', 'SELECT 1');
PREPARE stmt FROM @drop_5; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_6 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_api_key', 'SELECT 1');
PREPARE stmt FROM @drop_6; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_7 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_service_subject', 'SELECT 1');
PREPARE stmt FROM @drop_7; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_8 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_user_role', 'SELECT 1');
PREPARE stmt FROM @drop_8; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_9 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_role_permission', 'SELECT 1');
PREPARE stmt FROM @drop_9; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_10 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_role_menu', 'SELECT 1');
PREPARE stmt FROM @drop_10; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_11 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_user', 'SELECT 1');
PREPARE stmt FROM @drop_11; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_12 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_role', 'SELECT 1');
PREPARE stmt FROM @drop_12; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_13 = IF(@uuid_identity_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_dept', 'SELECT 1');
PREPARE stmt FROM @drop_13; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE IF NOT EXISTS sys_dept (
  id BINARY(16) PRIMARY KEY,
  parent_id BINARY(16) NULL,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_dept_parent FOREIGN KEY (parent_id) REFERENCES sys_dept(id) ON DELETE RESTRICT,
  INDEX idx_dept_parent_sort (parent_id, sort_order, id)
);

CREATE TABLE IF NOT EXISTS sys_role (
  id BINARY(16) PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  data_scope VARCHAR(32) NOT NULL DEFAULT 'ALL',
  dept_scope TEXT NULL
);

CREATE TABLE IF NOT EXISTS sys_user (
  id BINARY(16) PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  display_name VARCHAR(128) NOT NULL,
  email VARCHAR(128) NULL,
  phone_number VARCHAR(32) NULL,
  sex TINYINT NULL,
  avatar VARCHAR(512) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  login_ip VARCHAR(64) NULL,
  login_at TIMESTAMP NULL,
  dept_id BINARY(16) NULL,
  post_id BIGINT NULL,
  remark VARCHAR(500) NULL,
  must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
  failed_login_count INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMP NULL,
  credential_version BIGINT NOT NULL DEFAULT 1,
  last_password_changed_at TIMESTAMP NULL,
  permission_version BIGINT NOT NULL DEFAULT 1,
  mfa_required TINYINT NOT NULL DEFAULT 0,
  mfa_grace_until TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_user_dept FOREIGN KEY (dept_id) REFERENCES sys_dept(id) ON DELETE SET NULL,
  INDEX idx_sys_user_enabled (enabled),
  INDEX idx_user_dept (dept_id),
  INDEX idx_user_post (post_id)
);

CREATE TABLE IF NOT EXISTS sys_user_role (
  user_id BINARY(16) NOT NULL,
  role_id BINARY(16) NOT NULL,
  PRIMARY KEY (user_id, role_id),
  CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sys_role_permission (
  role_id BINARY(16) NOT NULL,
  permission_id BINARY(16) NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES sys_permission(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sys_role_menu (
  role_id BINARY(16) NOT NULL,
  menu_id BIGINT NOT NULL,
  PRIMARY KEY (role_id, menu_id),
  CONSTRAINT fk_role_menu_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_menu_menu FOREIGN KEY (menu_id) REFERENCES sys_menu(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sys_refresh_token (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BINARY(16) NOT NULL,
  session_id CHAR(36) NULL,
  refresh_family_id CHAR(36) NULL,
  client_id VARCHAR(128) NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  idle_expires_at TIMESTAMP NULL,
  access_expires_at TIMESTAMP NULL,
  access_token_id CHAR(36) NULL UNIQUE,
  revoked_at TIMESTAMP NULL,
  reused_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_refresh_token_user (user_id),
  INDEX idx_refresh_token_expiry (expires_at, revoked_at),
  INDEX idx_refresh_session_state (session_id, revoked_at),
  INDEX idx_refresh_family_state (refresh_family_id, revoked_at)
);

CREATE TABLE IF NOT EXISTS sys_auth_session (
  id CHAR(36) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  approved_scope TEXT NULL,
  refresh_family_id CHAR(36) NOT NULL,
  refresh_expires_at TIMESTAMP NOT NULL,
  idle_expires_at TIMESTAMP NOT NULL,
  last_seen_at TIMESTAMP NOT NULL,
  mfa_verified_at TIMESTAMP NULL,
  mfa_assurance VARCHAR(32) NULL,
  mfa_amr VARCHAR(128) NULL,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_auth_session_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_auth_session_user_state (user_id, revoked_at),
  INDEX idx_auth_session_family (refresh_family_id),
  INDEX idx_auth_session_expiry (refresh_expires_at, idle_expires_at, revoked_at)
);

CREATE TABLE IF NOT EXISTS sys_refresh_token_event (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  token_id BIGINT NULL,
  user_id BINARY(16) NULL,
  refresh_family_id CHAR(36) NULL,
  event_type VARCHAR(32) NOT NULL,
  client_id VARCHAR(128) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  detail VARCHAR(255) NULL,
  INDEX idx_refresh_event_family_time (refresh_family_id, created_at),
  INDEX idx_refresh_event_user_time (user_id, created_at)
);

CREATE TABLE IF NOT EXISTS sys_service_subject (
  id CHAR(36) PRIMARY KEY,
  code VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  owner_user_id BINARY(16) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_service_subject_owner FOREIGN KEY (owner_user_id) REFERENCES sys_user(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sys_api_key (
  id CHAR(36) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  subject_id CHAR(36) NULL,
  created_by BINARY(16) NULL,
  name VARCHAR(128) NOT NULL,
  key_prefix VARCHAR(24) NOT NULL UNIQUE,
  key_hash CHAR(64) NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  expires_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL,
  rotated_to CHAR(36) NULL,
  revoked_reason VARCHAR(255) NULL,
  last_used_at TIMESTAMP NULL,
  last_used_ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_api_key_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_api_key_subject FOREIGN KEY (subject_id) REFERENCES sys_service_subject(id) ON DELETE SET NULL,
  CONSTRAINT fk_api_key_creator FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE SET NULL,
  INDEX idx_api_key_user_state (user_id, revoked_at, expires_at),
  INDEX idx_api_key_subject_state (subject_id, revoked_at, expires_at)
);

CREATE TABLE IF NOT EXISTS sys_user_mfa (
  id CHAR(36) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  mfa_type VARCHAR(16) NOT NULL DEFAULT 'TOTP',
  secret_ciphertext BLOB NOT NULL,
  secret_nonce VARBINARY(12) NOT NULL,
  key_version INT NOT NULL DEFAULT 1,
  enabled TINYINT NOT NULL DEFAULT 0,
  enrolled_at TIMESTAMP NULL,
  last_used_at TIMESTAMP NULL,
  failed_attempt_count INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMP NULL,
  last_accepted_step BIGINT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT uq_user_mfa_user UNIQUE (user_id),
  CONSTRAINT fk_user_mfa_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_user_mfa_enabled (user_id, enabled),
  INDEX idx_user_mfa_locked (locked_until)
);

CREATE TABLE IF NOT EXISTS sys_mfa_recovery_code (
  id CHAR(36) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  batch_id CHAR(36) NOT NULL,
  code_hash CHAR(64) NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_mfa_recovery_user_hash UNIQUE (user_id, code_hash),
  CONSTRAINT fk_mfa_recovery_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_mfa_recovery_batch (user_id, batch_id),
  INDEX idx_mfa_recovery_active (user_id, used_at)
);

CREATE TABLE IF NOT EXISTS sys_auth_challenge (
  id CHAR(36) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  purpose VARCHAR(16) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  session_id CHAR(36) NULL,
  context_hash CHAR(64) NULL,
  expires_at TIMESTAMP NOT NULL,
  attempt_count INT NOT NULL DEFAULT 0,
  consumed_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_auth_challenge_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_auth_challenge_session FOREIGN KEY (session_id) REFERENCES sys_auth_session(id) ON DELETE CASCADE,
  INDEX idx_auth_challenge_user_state (user_id, purpose, consumed_at, expires_at),
  INDEX idx_auth_challenge_session (session_id, purpose, consumed_at)
);

INSERT IGNORE INTO sys_dept (id, parent_id, code, name, sort_order)
VALUES (UUID_TO_BIN('ec955baa-6e89-5626-bccf-7106d2d3cb8b', 0), NULL, 'ROOT', 'Default Organization', 0);
INSERT IGNORE INTO sys_role (id, code, name, data_scope)
VALUES (UUID_TO_BIN('2f57b9e0-836d-5f15-97a3-d4be27dc0bef', 0), 'ADMIN', 'Administrator', 'ALL'),
       (UUID_TO_BIN('30cfca67-d34c-5b13-a6ec-7bddce4f62f7', 0), 'USER', 'User', 'SELF');
INSERT IGNORE INTO sys_user (id, username, password_hash, display_name, dept_id)
VALUES (UUID_TO_BIN('5faed4bb-63af-5158-bd3c-1200c539cfd9', 0), 'admin',
        '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
        'Administrator', UUID_TO_BIN('ec955baa-6e89-5626-bccf-7106d2d3cb8b', 0));
INSERT IGNORE INTO sys_user_role (user_id, role_id)
VALUES (UUID_TO_BIN('5faed4bb-63af-5158-bd3c-1200c539cfd9', 0), UUID_TO_BIN('2f57b9e0-836d-5f15-97a3-d4be27dc0bef', 0));
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT UUID_TO_BIN('2f57b9e0-836d-5f15-97a3-d4be27dc0bef', 0), id FROM sys_permission;
-- 读取边界明确使用 BIN_TO_UUID；应用接口只返回规范小写字符串。
SET @uuid_identity_admin_id = (SELECT BIN_TO_UUID(id, 0) FROM sys_role WHERE code = 'ADMIN' LIMIT 1);
INSERT IGNORE INTO sys_uuid_identity_migration (migration_key)
VALUES ('V46_UUID_IDENTITY_CORE');
