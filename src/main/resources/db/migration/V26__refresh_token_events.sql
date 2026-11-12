CREATE TABLE IF NOT EXISTS sys_refresh_token_event (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  token_id BIGINT NULL,
  user_id BIGINT NULL,
  refresh_family_id CHAR(36) NULL,
  event_type VARCHAR(32) NOT NULL,
  client_id VARCHAR(128) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  detail VARCHAR(255) NULL,
  INDEX idx_refresh_event_family_time (refresh_family_id, created_at),
  INDEX idx_refresh_event_user_time (user_id, created_at)
);
