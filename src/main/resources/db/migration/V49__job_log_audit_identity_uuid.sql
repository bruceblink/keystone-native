-- 一次性重建任务、日志和刷新令牌事件身份。
-- 新业务 ID 使用 UUIDv7；MySQL 使用 BINARY(16)，固定种子使用 UUIDv5。
-- 固定 UUID 写入使用 UUID_TO_BIN(uuid, 0)，文本读取使用 BIN_TO_UUID(id, 0)。
CREATE TABLE IF NOT EXISTS sys_uuid_job_log_migration (
  migration_key VARCHAR(64) PRIMARY KEY,
  completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

SET @uuid_job_log_should_rebuild = (SELECT IF(COUNT(*) = 0, 1, 0)
  FROM sys_uuid_job_log_migration WHERE migration_key = 'V49_JOB_LOG_AUDIT');

SET FOREIGN_KEY_CHECKS = 0;
SET @drop_job_log_0 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_job_log', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_0; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_job_log_1 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_job', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_1; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_job_log_2 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_login_log', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_2; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_job_log_3 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_operation_log', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_3; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_job_log_4 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_security_event', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_4; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_job_log_5 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_refresh_token_event', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_5; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_job_log_6 = IF(@uuid_job_log_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_refresh_token', 'SELECT 1');
PREPARE stmt FROM @drop_job_log_6; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE IF NOT EXISTS sys_job (
  id BINARY(16) PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  job_group VARCHAR(64) NOT NULL DEFAULT 'DEFAULT',
  invoke_target VARCHAR(255) NOT NULL,
  job_params TEXT NULL,
  cron VARCHAR(128) NOT NULL,
  concurrent BOOLEAN NOT NULL DEFAULT TRUE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  remark VARCHAR(255) NULL,
  last_status VARCHAR(16) NULL,
  last_run_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sys_job_log (
  id BINARY(16) PRIMARY KEY,
  job_id BINARY(16) NULL,
  job_code VARCHAR(64) NOT NULL,
  job_name VARCHAR(128) NOT NULL,
  job_group VARCHAR(64) NOT NULL,
  invoke_target VARCHAR(255) NOT NULL,
  job_params TEXT NULL,
  cron VARCHAR(128) NOT NULL,
  trigger_type TINYINT NOT NULL,
  status TINYINT NOT NULL,
  job_message VARCHAR(500) NOT NULL,
  exception_info TEXT NULL,
  started_at TIMESTAMP(6) NOT NULL,
  finished_at TIMESTAMP(6) NULL,
  duration_ms BIGINT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_job_log_job FOREIGN KEY (job_id) REFERENCES sys_job(id) ON DELETE SET NULL,
  INDEX idx_job_log_job_time (job_id, started_at),
  INDEX idx_job_log_status_time (status, started_at)
);

CREATE TABLE IF NOT EXISTS sys_login_log (
  id BINARY(16) PRIMARY KEY,
  username VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL,
  ip_address VARCHAR(64) NULL,
  message VARCHAR(255) NULL,
  user_agent VARCHAR(512) NULL,
  login_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_login_log_user_time (username, login_at),
  INDEX idx_login_log_status_time (status, login_at)
);

CREATE TABLE IF NOT EXISTS sys_operation_log (
  id BINARY(16) PRIMARY KEY,
  actor_username VARCHAR(64) NOT NULL,
  action VARCHAR(32) NOT NULL,
  resource VARCHAR(64) NOT NULL,
  resource_id VARCHAR(64) NULL,
  detail VARCHAR(1000) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_operation_log_created (created_at, id),
  INDEX idx_operation_log_actor (actor_username, created_at)
);

CREATE TABLE IF NOT EXISTS sys_security_event (
  id BINARY(16) PRIMARY KEY,
  event_type VARCHAR(32) NOT NULL,
  actor VARCHAR(128) NULL,
  credential_type VARCHAR(32) NULL,
  credential_id VARCHAR(128) NULL,
  source_ip VARCHAR(64) NULL,
  resource VARCHAR(128) NULL,
  action VARCHAR(128) NULL,
  outcome VARCHAR(32) NOT NULL,
  detail VARCHAR(255) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_security_event_type_time (event_type, created_at),
  INDEX idx_security_event_actor_time (actor, created_at),
  INDEX idx_security_event_outcome_time (outcome, created_at),
  INDEX idx_security_event_credential_time (credential_id, created_at)
);

CREATE TABLE IF NOT EXISTS sys_refresh_token (
  id BINARY(16) PRIMARY KEY,
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
  CONSTRAINT fk_refresh_token_user_v49 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_refresh_token_user (user_id),
  INDEX idx_refresh_token_expiry (expires_at, revoked_at),
  INDEX idx_refresh_session_state (session_id, revoked_at),
  INDEX idx_refresh_family_state (refresh_family_id, revoked_at)
);

CREATE TABLE IF NOT EXISTS sys_refresh_token_event (
  id BINARY(16) PRIMARY KEY,
  token_id BINARY(16) NULL,
  user_id BINARY(16) NULL,
  refresh_family_id CHAR(36) NULL,
  event_type VARCHAR(32) NOT NULL,
  client_id VARCHAR(128) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  detail VARCHAR(255) NULL,
  CONSTRAINT fk_refresh_event_token_v49 FOREIGN KEY (token_id) REFERENCES sys_refresh_token(id) ON DELETE SET NULL,
  CONSTRAINT fk_refresh_event_user_v49 FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE SET NULL,
  INDEX idx_refresh_event_family_time (refresh_family_id, created_at),
  INDEX idx_refresh_event_user_time (user_id, created_at)
);

INSERT IGNORE INTO sys_uuid_job_log_migration (migration_key)
VALUES ('V49_JOB_LOG_AUDIT');
