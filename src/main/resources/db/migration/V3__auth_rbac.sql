CREATE TABLE IF NOT EXISTS sys_role (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS sys_permission (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  code VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL
);

CREATE TABLE IF NOT EXISTS sys_user_role (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sys_role_permission (
  role_id BIGINT NOT NULL,
  permission_id BIGINT NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES sys_permission(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sys_refresh_token (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE
);
CREATE INDEX idx_refresh_token_user ON sys_refresh_token(user_id);
CREATE INDEX idx_refresh_token_expiry ON sys_refresh_token(expires_at, revoked_at);

INSERT INTO sys_role (code, name)
SELECT 'ADMIN', 'Administrator'
WHERE NOT EXISTS (SELECT 1 FROM sys_role WHERE code = 'ADMIN');
INSERT INTO sys_role (code, name)
SELECT 'USER', 'User'
WHERE NOT EXISTS (SELECT 1 FROM sys_role WHERE code = 'USER');

INSERT INTO sys_permission (code, name)
SELECT 'user:read', 'View users'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'user:read');
INSERT INTO sys_permission (code, name)
SELECT 'user:write', 'Manage users'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'user:write');
INSERT INTO sys_permission (code, name)
SELECT 'role:read', 'View roles'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'role:read');

INSERT IGNORE INTO sys_user_role (user_id, role_id)
SELECT u.id, r.id FROM sys_user u CROSS JOIN sys_role r
WHERE u.username = 'admin' AND r.code = 'ADMIN';
INSERT IGNORE INTO sys_user_role (user_id, role_id)
SELECT u.id, r.id FROM sys_user u CROSS JOIN sys_role r
WHERE u.username <> 'admin' AND r.code = 'USER';

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.code = 'ADMIN';
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id FROM sys_role r JOIN sys_permission p ON p.code = 'user:read' WHERE r.code = 'USER';
