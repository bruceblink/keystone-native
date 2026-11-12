-- 登录失败限流记录只保存哈希键，窗口结束后由下一次失败覆盖计数。
CREATE TABLE IF NOT EXISTS sys_login_rate_limit (
  scope_key CHAR(64) PRIMARY KEY,
  window_started_at TIMESTAMP NOT NULL,
  attempt_count INT NOT NULL,
  blocked_until TIMESTAMP NULL
);
SET @add_login_rate_index = (SELECT IF(COUNT(*) = 0, 'CREATE INDEX idx_login_rate_blocked ON sys_login_rate_limit(blocked_until)', 'SELECT 1') FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'sys_login_rate_limit' AND index_name = 'idx_login_rate_blocked');
PREPARE stmt FROM @add_login_rate_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;
