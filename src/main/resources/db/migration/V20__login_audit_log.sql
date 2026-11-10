CREATE TABLE IF NOT EXISTS sys_login_log (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL,
  ip_address VARCHAR(64) NULL,
  message VARCHAR(255) NULL,
  user_agent VARCHAR(512) NULL,
  login_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_login_log_user_time (username, login_at),
  INDEX idx_login_log_status_time (status, login_at)
);
