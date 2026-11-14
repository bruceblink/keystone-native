-- 持久化 JWT 公钥目录。公钥材料不是秘密，但只能发布已登记且未到期的 key。
CREATE TABLE IF NOT EXISTS sys_jwt_key_registry (
  id BINARY(16) PRIMARY KEY,
  key_id VARCHAR(128) NOT NULL UNIQUE,
  kty VARCHAR(16) NOT NULL,
  alg VARCHAR(16) NOT NULL,
  use_type VARCHAR(16) NOT NULL,
  modulus TEXT NOT NULL,
  exponent VARCHAR(128) NOT NULL,
  state VARCHAR(16) NOT NULL,
  expires_at TIMESTAMP NULL,
  retired_at TIMESTAMP NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  INDEX idx_jwt_key_registry_state_expiry (state, expires_at),
  INDEX idx_jwt_key_registry_updated (updated_at)
);
