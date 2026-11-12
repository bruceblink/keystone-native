CREATE TABLE IF NOT EXISTS sys_api_key (
  id CHAR(36) PRIMARY KEY,
  user_id BIGINT NOT NULL,
  name VARCHAR(128) NOT NULL,
  key_prefix VARCHAR(24) NOT NULL UNIQUE,
  key_hash CHAR(64) NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  expires_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL,
  last_used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_api_key_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE
);
CREATE INDEX idx_api_key_user_state ON sys_api_key(user_id, revoked_at, expires_at);
