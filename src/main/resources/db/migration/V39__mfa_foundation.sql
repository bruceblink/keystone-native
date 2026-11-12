-- 管理员 TOTP、一次性恢复码和认证挑战的数据基础。
-- TOTP 密钥使用加密密文保存；本迁移不启用任何现有用户的 MFA。

SET @add_mfa_required = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_user ADD COLUMN mfa_required TINYINT NOT NULL DEFAULT 0 AFTER permission_version',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'mfa_required');
PREPARE stmt FROM @add_mfa_required; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_mfa_grace_until = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_user ADD COLUMN mfa_grace_until TIMESTAMP NULL AFTER mfa_required',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'mfa_grace_until');
PREPARE stmt FROM @add_mfa_grace_until; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS sys_user_mfa (
  id CHAR(36) PRIMARY KEY,
  user_id BIGINT NOT NULL,
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
  CONSTRAINT chk_user_mfa_type CHECK (mfa_type = 'TOTP'),
  CONSTRAINT chk_user_mfa_key_version CHECK (key_version > 0),
  CONSTRAINT fk_user_mfa_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_user_mfa_enabled (user_id, enabled),
  INDEX idx_user_mfa_locked (locked_until)
);

CREATE TABLE IF NOT EXISTS sys_mfa_recovery_code (
  id CHAR(36) PRIMARY KEY,
  user_id BIGINT NOT NULL,
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
  user_id BIGINT NOT NULL,
  purpose VARCHAR(16) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  session_id CHAR(36) NULL,
  context_hash CHAR(64) NULL,
  expires_at TIMESTAMP NOT NULL,
  attempt_count INT NOT NULL DEFAULT 0,
  consumed_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT chk_auth_challenge_purpose CHECK (purpose IN ('LOGIN', 'STEP_UP', 'ENROLL', 'RECOVERY')),
  CONSTRAINT fk_auth_challenge_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_auth_challenge_session FOREIGN KEY (session_id) REFERENCES sys_auth_session(id) ON DELETE CASCADE,
  INDEX idx_auth_challenge_user_state (user_id, purpose, consumed_at, expires_at),
  INDEX idx_auth_challenge_session (session_id, purpose, consumed_at)
);

SET @add_mfa_verified_at = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_auth_session ADD COLUMN mfa_verified_at TIMESTAMP NULL AFTER last_seen_at',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_auth_session' AND column_name = 'mfa_verified_at');
PREPARE stmt FROM @add_mfa_verified_at; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_mfa_assurance = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_auth_session ADD COLUMN mfa_assurance VARCHAR(32) NULL AFTER mfa_verified_at',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_auth_session' AND column_name = 'mfa_assurance');
PREPARE stmt FROM @add_mfa_assurance; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_mfa_amr = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_auth_session ADD COLUMN mfa_amr VARCHAR(128) NULL AFTER mfa_assurance',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_auth_session' AND column_name = 'mfa_amr');
PREPARE stmt FROM @add_mfa_amr; EXECUTE stmt; DEALLOCATE PREPARE stmt;
