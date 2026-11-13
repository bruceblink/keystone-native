-- 补充安全事件的会话、范围和请求标识，便于还原授权决策上下文。
-- 通过 information_schema 判断列和索引，重复执行时保持无副作用。
SET @add_security_event_session_id = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD COLUMN session_id BINARY(16) NULL AFTER credential_id',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND column_name = 'session_id');
PREPARE stmt FROM @add_security_event_session_id; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_security_event_scope = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD COLUMN scope TEXT NULL AFTER action',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND column_name = 'scope');
PREPARE stmt FROM @add_security_event_scope; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_security_event_request_id = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD COLUMN request_id VARCHAR(128) NULL AFTER scope',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND column_name = 'request_id');
PREPARE stmt FROM @add_security_event_request_id; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_security_event_session_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD INDEX idx_security_event_session_time (session_id, created_at)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND index_name = 'idx_security_event_session_time');
PREPARE stmt FROM @add_security_event_session_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_security_event_request_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD INDEX idx_security_event_request_time (request_id, created_at)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND index_name = 'idx_security_event_request_time');
PREPARE stmt FROM @add_security_event_request_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;
