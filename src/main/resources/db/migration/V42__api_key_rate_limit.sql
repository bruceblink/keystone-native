-- API Key 失败认证限流只保存哈希后的来源和凭据维度。
CREATE TABLE IF NOT EXISTS sys_api_key_rate_limit (
  scope_key CHAR(64) PRIMARY KEY,
  window_started_at TIMESTAMP NOT NULL,
  attempt_count INT NOT NULL,
  blocked_until TIMESTAMP NULL,
  INDEX idx_api_key_rate_blocked (blocked_until)
);
