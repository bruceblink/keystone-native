-- 为 MFA 认证请求过期清理提供有界索引扫描；重复执行和部分执行后重跑均安全。
SET @add_auth_challenge_expiry_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_auth_challenge ADD INDEX idx_auth_challenge_expiry (expires_at)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_auth_challenge'
    AND index_name = 'idx_auth_challenge_expiry');
PREPARE stmt FROM @add_auth_challenge_expiry_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_auth_challenge_session_issue_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_auth_challenge ADD INDEX idx_auth_challenge_session_issue (user_id, session_id, purpose, created_at)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_auth_challenge'
    AND index_name = 'idx_auth_challenge_session_issue');
PREPARE stmt FROM @add_auth_challenge_session_issue_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;
