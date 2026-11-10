CREATE TABLE IF NOT EXISTS sys_menu (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  parent_id BIGINT NULL,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  path VARCHAR(255) NULL,
  component VARCHAR(255) NULL,
  menu_type VARCHAR(16) NOT NULL DEFAULT 'MENU',
  permission VARCHAR(128) NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT fk_menu_parent FOREIGN KEY (parent_id) REFERENCES sys_menu(id) ON DELETE RESTRICT
);
CREATE INDEX idx_menu_parent_sort ON sys_menu(parent_id, sort_order, id);

CREATE TABLE IF NOT EXISTS sys_role_menu (
  role_id BIGINT NOT NULL,
  menu_id BIGINT NOT NULL,
  PRIMARY KEY (role_id, menu_id),
  CONSTRAINT fk_role_menu_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_menu_menu FOREIGN KEY (menu_id) REFERENCES sys_menu(id) ON DELETE CASCADE
);

INSERT INTO sys_menu (parent_id, code, name, path, menu_type, sort_order)
SELECT NULL, 'dashboard', 'Dashboard', '/dashboard', 'MENU', 0
WHERE NOT EXISTS (SELECT 1 FROM sys_menu WHERE code = 'dashboard');
INSERT INTO sys_menu (parent_id, code, name, path, menu_type, sort_order)
SELECT NULL, 'system', 'System Management', '/system', 'CATALOG', 10
WHERE NOT EXISTS (SELECT 1 FROM sys_menu WHERE code = 'system');
INSERT INTO sys_menu (parent_id, code, name, path, menu_type, permission, sort_order)
SELECT (SELECT id FROM sys_menu WHERE code = 'system'), 'system:user', 'Users', '/system/users', 'MENU', 'user:read', 0
WHERE NOT EXISTS (SELECT 1 FROM sys_menu WHERE code = 'system:user');
INSERT IGNORE INTO sys_role_menu (role_id, menu_id)
SELECT r.id, m.id FROM sys_role r CROSS JOIN sys_menu m WHERE r.code = 'ADMIN';
