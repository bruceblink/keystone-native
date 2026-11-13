-- 统一保存安全边界事件；不保存密码、令牌或完整 API Key。
CREATE TABLE IF NOT EXISTS sys_security_event (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  event_type VARCHAR(32) NOT NULL,
  actor VARCHAR(128) NULL,
  credential_type VARCHAR(32) NULL,
  source_ip VARCHAR(64) NULL,
  resource VARCHAR(128) NULL,
  action VARCHAR(128) NULL,
  outcome VARCHAR(32) NOT NULL,
  detail VARCHAR(255) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_security_event_type_time (event_type, created_at),
  INDEX idx_security_event_actor_time (actor, created_at),
  INDEX idx_security_event_outcome_time (outcome, created_at)
);
