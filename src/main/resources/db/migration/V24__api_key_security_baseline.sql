CREATE TABLE IF NOT EXISTS sys_service_subject (
  id CHAR(36) PRIMARY KEY,
  code VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  owner_user_id BIGINT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_service_subject_owner FOREIGN KEY (owner_user_id) REFERENCES sys_user(id) ON DELETE SET NULL
);

SET @add_subject_id = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD COLUMN subject_id CHAR(36) NULL AFTER user_id',
  'SELECT 1') FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND column_name = 'subject_id');
PREPARE stmt FROM @add_subject_id; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_created_by = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD COLUMN created_by BIGINT NULL AFTER subject_id',
  'SELECT 1') FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND column_name = 'created_by');
PREPARE stmt FROM @add_created_by; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_rotated_to = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD COLUMN rotated_to CHAR(36) NULL AFTER revoked_at',
  'SELECT 1') FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND column_name = 'rotated_to');
PREPARE stmt FROM @add_rotated_to; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_revoked_reason = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD COLUMN revoked_reason VARCHAR(255) NULL AFTER rotated_to',
  'SELECT 1') FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND column_name = 'revoked_reason');
PREPARE stmt FROM @add_revoked_reason; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_last_used_ip = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD COLUMN last_used_ip VARCHAR(64) NULL AFTER last_used_at',
  'SELECT 1') FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND column_name = 'last_used_ip');
PREPARE stmt FROM @add_last_used_ip; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_subject_index = (SELECT IF(COUNT(*) = 0,
  'CREATE INDEX idx_api_key_subject_state ON sys_api_key(subject_id, revoked_at, expires_at)',
  'SELECT 1') FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND index_name = 'idx_api_key_subject_state');
PREPARE stmt FROM @add_subject_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

INSERT INTO sys_service_subject (id, code, name, owner_user_id)
SELECT UUID(), CONCAT('user:', u.id), CONCAT('User API keys: ', u.username), u.id
FROM sys_user u
WHERE NOT EXISTS (SELECT 1 FROM sys_service_subject s WHERE s.code = CONCAT('user:', u.id));

UPDATE sys_api_key k
JOIN sys_service_subject s ON s.code = CONCAT('user:', k.user_id)
SET k.subject_id = s.id
WHERE k.subject_id IS NULL;

SET @add_subject_fk = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD CONSTRAINT fk_api_key_subject FOREIGN KEY (subject_id) REFERENCES sys_service_subject(id) ON DELETE SET NULL',
  'SELECT 1') FROM information_schema.table_constraints
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND constraint_name = 'fk_api_key_subject');
PREPARE stmt FROM @add_subject_fk; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_created_by_fk = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_api_key ADD CONSTRAINT fk_api_key_creator FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE SET NULL',
  'SELECT 1') FROM information_schema.table_constraints
  WHERE table_schema = DATABASE() AND table_name = 'sys_api_key' AND constraint_name = 'fk_api_key_creator');
PREPARE stmt FROM @add_created_by_fk; EXECUTE stmt; DEALLOCATE PREPARE stmt;

INSERT INTO sys_permission (code, name)
SELECT 'api-key:create', 'Create API keys'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'api-key:create');
INSERT INTO sys_permission (code, name)
SELECT 'api-key:read', 'Read API key metadata'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'api-key:read');
INSERT INTO sys_permission (code, name)
SELECT 'api-key:revoke', 'Revoke API keys'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'api-key:revoke');
INSERT INTO sys_permission (code, name)
SELECT 'api-key:rotate', 'Rotate API keys'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'api-key:rotate');

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p
WHERE r.code = 'ADMIN' AND p.code IN ('api-key:create', 'api-key:read', 'api-key:revoke', 'api-key:rotate');
