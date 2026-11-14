-- 服务端生成并短期保存 PKCE verifier；回调只接受 code 和 state。
SET @add_oidc_code_verifier = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_oidc_auth_request ADD COLUMN code_verifier VARCHAR(128) NOT NULL DEFAULT '''' AFTER code_challenge',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_oidc_auth_request' AND column_name = 'code_verifier');
PREPARE stmt FROM @add_oidc_code_verifier; EXECUTE stmt; DEALLOCATE PREPARE stmt;
