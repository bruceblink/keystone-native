-- 建立资源读写权限，并把权限授予 ADMIN 角色。
INSERT INTO sys_permission (code, name)
SELECT 'department:read', 'Read departments'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'department:read');
INSERT INTO sys_permission (code, name)
SELECT 'department:write', 'Manage departments'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'department:write');
INSERT INTO sys_permission (code, name)
SELECT 'dictionary:read', 'Read dictionaries'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'dictionary:read');
INSERT INTO sys_permission (code, name)
SELECT 'dictionary:write', 'Manage dictionaries'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'dictionary:write');
INSERT INTO sys_permission (code, name)
SELECT 'post:read', 'Read posts'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'post:read');
INSERT INTO sys_permission (code, name)
SELECT 'post:write', 'Manage posts'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'post:write');
INSERT INTO sys_permission (code, name)
SELECT 'config:read', 'Read system configuration'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'config:read');
INSERT INTO sys_permission (code, name)
SELECT 'config:write', 'Manage system configuration'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'config:write');

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
CROSS JOIN sys_permission p
WHERE r.code = 'ADMIN'
  AND p.code IN (
    'department:read', 'department:write',
    'dictionary:read', 'dictionary:write',
    'post:read', 'post:write',
    'config:read', 'config:write'
  );

-- 保留普通用户对原有只读资源的访问范围，不授予写权限。
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
CROSS JOIN sys_permission p
WHERE r.code = 'USER'
  AND p.code IN ('department:read', 'dictionary:read', 'post:read');
