-- MFA 验证失败限流只保存哈希后的主体和来源地址维度。
CREATE TABLE IF NOT EXISTS sys_mfa_rate_limit (
  scope_key CHAR(64) PRIMARY KEY,
  window_started_at TIMESTAMP NOT NULL,
  attempt_count INT NOT NULL,
  blocked_until TIMESTAMP NULL,
  INDEX idx_mfa_rate_blocked (blocked_until)
);
