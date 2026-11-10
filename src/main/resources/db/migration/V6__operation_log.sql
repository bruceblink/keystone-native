CREATE TABLE IF NOT EXISTS sys_operation_log (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  actor_username VARCHAR(64) NOT NULL,
  action VARCHAR(32) NOT NULL,
  resource VARCHAR(64) NOT NULL,
  resource_id VARCHAR(64) NULL,
  detail VARCHAR(1000) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_operation_log_created ON sys_operation_log(created_at, id);
CREATE INDEX idx_operation_log_actor ON sys_operation_log(actor_username, created_at);
