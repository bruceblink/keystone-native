-- OIDC 外部主体映射。每个 issuer 与 subject 组合只能绑定一个本地用户。
SET @add_oidc_issuer = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_user ADD COLUMN oidc_issuer VARCHAR(255) NULL AFTER email',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'oidc_issuer');
PREPARE stmt FROM @add_oidc_issuer; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_oidc_subject = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_user ADD COLUMN oidc_subject VARCHAR(255) NULL AFTER oidc_issuer',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND column_name = 'oidc_subject');
PREPARE stmt FROM @add_oidc_subject; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_oidc_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_user ADD UNIQUE INDEX uq_sys_user_oidc_identity (oidc_issuer, oidc_subject)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_user' AND index_name = 'uq_sys_user_oidc_identity');
PREPARE stmt FROM @add_oidc_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS sys_oidc_auth_request (
  id BINARY(16) PRIMARY KEY,
  state_hash CHAR(64) NOT NULL UNIQUE,
  nonce_hash CHAR(64) NOT NULL,
  code_challenge CHAR(128) NOT NULL,
  code_challenge_method VARCHAR(16) NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  redirect_uri VARCHAR(1024) NOT NULL,
  expires_at TIMESTAMP(6) NOT NULL,
  consumed_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_oidc_auth_request_expiry (expires_at, consumed_at)
);
