-- 为安全事件增加非秘密凭据标识，区分同一主体下的多个 API Key。
SET @add_security_event_credential_id = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD COLUMN credential_id VARCHAR(128) NULL AFTER credential_type',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND column_name = 'credential_id');
PREPARE stmt FROM @add_security_event_credential_id; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_security_event_credential_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_security_event ADD INDEX idx_security_event_credential_time (credential_id, created_at)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_security_event' AND index_name = 'idx_security_event_credential_time');
PREPARE stmt FROM @add_security_event_credential_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;
