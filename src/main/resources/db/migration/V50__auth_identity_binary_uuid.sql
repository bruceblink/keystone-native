-- 一次性重建认证、MFA、服务主体和 API Key 身份表。
-- 这些表在 clean-break 迁移中不保留旧文本或整数身份；生产执行前必须完成备份和回滚演练。
-- 新业务 ID 由应用生成 UUIDv7，固定目录仍使用 UUIDv5；MySQL 边界使用
-- UUID_TO_BIN(..., 0) 写入、BIN_TO_UUID(..., 0) 读取。ORM 使用同一 16 字节顺序绑定。

CREATE TABLE IF NOT EXISTS sys_uuid_auth_identity_migration (
  migration_key VARCHAR(64) PRIMARY KEY,
  completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

SET @uuid_auth_should_rebuild = (SELECT IF(COUNT(*) = 0, 1, 0)
  FROM sys_uuid_auth_identity_migration
  WHERE migration_key = 'V50_AUTH_IDENTITY_BINARY_UUID');

-- 迁移允许破坏性更新。关闭外键检查后按依赖逆序重建，保证失败重跑不会留下旧列类型。
SET FOREIGN_KEY_CHECKS = 0;
SET @drop_auth_0 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_auth_challenge', 'DO 0');
PREPARE stmt FROM @drop_auth_0; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_1 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_mfa_recovery_code', 'DO 0');
PREPARE stmt FROM @drop_auth_1; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_2 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_user_mfa', 'DO 0');
PREPARE stmt FROM @drop_auth_2; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_3 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_api_key', 'DO 0');
PREPARE stmt FROM @drop_auth_3; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_4 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_service_subject', 'DO 0');
PREPARE stmt FROM @drop_auth_4; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_5 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_refresh_token_event', 'DO 0');
PREPARE stmt FROM @drop_auth_5; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_6 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_refresh_token', 'DO 0');
PREPARE stmt FROM @drop_auth_6; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_auth_7 = IF(@uuid_auth_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_auth_session', 'DO 0');
PREPARE stmt FROM @drop_auth_7; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE IF NOT EXISTS sys_auth_session (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  approved_scope TEXT NULL,
  refresh_family_id BINARY(16) NOT NULL,
  refresh_expires_at TIMESTAMP NOT NULL,
  idle_expires_at TIMESTAMP NOT NULL,
  last_seen_at TIMESTAMP NOT NULL,
  mfa_verified_at TIMESTAMP NULL,
  mfa_assurance VARCHAR(32) NULL,
  mfa_amr VARCHAR(128) NULL,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_auth_session_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_auth_session_user_state_v50 (user_id, revoked_at),
  INDEX idx_auth_session_family_v50 (refresh_family_id),
  INDEX idx_auth_session_expiry_v50 (refresh_expires_at, idle_expires_at, revoked_at)
);

CREATE TABLE IF NOT EXISTS sys_refresh_token (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  session_id BINARY(16) NULL,
  refresh_family_id BINARY(16) NULL,
  client_id VARCHAR(128) NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  idle_expires_at TIMESTAMP NULL,
  access_expires_at TIMESTAMP NULL,
  access_token_id BINARY(16) NULL UNIQUE,
  revoked_at TIMESTAMP NULL,
  reused_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_refresh_token_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_token_session_v50 FOREIGN KEY (session_id) REFERENCES sys_auth_session(id) ON DELETE CASCADE,
  INDEX idx_refresh_token_user_v50 (user_id),
  INDEX idx_refresh_token_expiry_v50 (expires_at, revoked_at),
  INDEX idx_refresh_session_state_v50 (session_id, revoked_at),
  INDEX idx_refresh_family_state_v50 (refresh_family_id, revoked_at)
);

CREATE TABLE IF NOT EXISTS sys_refresh_token_event (
  id BINARY(16) PRIMARY KEY,
  token_id BINARY(16) NULL,
  user_id BINARY(16) NULL,
  refresh_family_id BINARY(16) NULL,
  event_type VARCHAR(32) NOT NULL,
  client_id VARCHAR(128) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  detail VARCHAR(255) NULL,
  CONSTRAINT fk_refresh_event_token_v50 FOREIGN KEY (token_id) REFERENCES sys_refresh_token(id) ON DELETE SET NULL,
  CONSTRAINT fk_refresh_event_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE SET NULL,
  INDEX idx_refresh_event_family_time_v50 (refresh_family_id, created_at),
  INDEX idx_refresh_event_user_time_v50 (user_id, created_at)
);

CREATE TABLE IF NOT EXISTS sys_service_subject (
  id BINARY(16) PRIMARY KEY,
  code VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  owner_user_id BINARY(16) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_service_subject_owner_v50 FOREIGN KEY (owner_user_id) REFERENCES sys_user(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sys_api_key (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  subject_id BINARY(16) NULL,
  created_by BINARY(16) NULL,
  name VARCHAR(128) NOT NULL,
  key_prefix VARCHAR(24) NOT NULL UNIQUE,
  key_hash CHAR(64) NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  expires_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL,
  rotated_to BINARY(16) NULL,
  revoked_reason VARCHAR(255) NULL,
  last_used_at TIMESTAMP NULL,
  last_used_ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_api_key_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_api_key_subject_v50 FOREIGN KEY (subject_id) REFERENCES sys_service_subject(id) ON DELETE SET NULL,
  CONSTRAINT fk_api_key_creator_v50 FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE SET NULL,
  INDEX idx_api_key_user_state_v50 (user_id, revoked_at, expires_at),
  INDEX idx_api_key_subject_state_v50 (subject_id, revoked_at, expires_at)
);

CREATE TABLE IF NOT EXISTS sys_user_mfa (
  id BINARY(16) PRIMARY KEY,
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
  CONSTRAINT uq_user_mfa_user_v50 UNIQUE (user_id),
  CONSTRAINT fk_user_mfa_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_user_mfa_enabled_v50 (user_id, enabled),
  INDEX idx_user_mfa_locked_v50 (locked_until)
);

CREATE TABLE IF NOT EXISTS sys_mfa_recovery_code (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  batch_id BINARY(16) NOT NULL,
  code_hash CHAR(64) NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_mfa_recovery_user_hash_v50 UNIQUE (user_id, code_hash),
  CONSTRAINT fk_mfa_recovery_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_mfa_recovery_batch_v50 (user_id, batch_id),
  INDEX idx_mfa_recovery_active_v50 (user_id, used_at)
);

CREATE TABLE IF NOT EXISTS sys_auth_challenge (
  id BINARY(16) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  purpose VARCHAR(16) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  session_id BINARY(16) NULL,
  context_hash CHAR(64) NULL,
  expires_at TIMESTAMP NOT NULL,
  attempt_count INT NOT NULL DEFAULT 0,
  consumed_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_auth_challenge_user_v50 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_auth_challenge_session_v50 FOREIGN KEY (session_id) REFERENCES sys_auth_session(id) ON DELETE CASCADE,
  INDEX idx_auth_challenge_user_state_v50 (user_id, purpose, consumed_at, expires_at),
  INDEX idx_auth_challenge_session_v50 (session_id, purpose, consumed_at)
);

-- 让迁移检查同时覆盖 UUID_TO_BIN/BIN_TO_UUID 的字节顺序约定。
SET @uuid_auth_round_trip = BIN_TO_UUID(UUID_TO_BIN('00000000-0000-7000-8000-000000000000', 0), 0);
INSERT IGNORE INTO sys_uuid_auth_identity_migration (migration_key)
VALUES ('V50_AUTH_IDENTITY_BINARY_UUID');
