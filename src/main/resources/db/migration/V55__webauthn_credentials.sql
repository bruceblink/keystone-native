-- WebAuthn 凭据只保存公钥、计数器和用户关联；私钥始终保留在认证器中。
CREATE TABLE IF NOT EXISTS sys_webauthn_credential (
  credential_id VARCHAR(512) PRIMARY KEY,
  user_id BINARY(16) NOT NULL,
  username VARCHAR(64) NOT NULL,
  public_key VARBINARY(4096) NOT NULL,
  public_key_algorithm BIGINT NOT NULL,
  counter BIGINT NOT NULL,
  aaguid BINARY(16) NULL,
  transports VARCHAR(128) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_webauthn_user_credential (user_id, credential_id),
  INDEX idx_webauthn_username (username),
  CONSTRAINT fk_webauthn_credential_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE
);
