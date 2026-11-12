-- 为剩余资源建立稳定权限码，并把原有用户和管理员访问边界迁移到权限集合。
INSERT INTO sys_permission (code, name)
SELECT 'menu:read', 'Read menus'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'menu:read');
INSERT INTO sys_permission (code, name)
SELECT 'menu:write', 'Manage menus'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'menu:write');
INSERT INTO sys_permission (code, name)
SELECT 'job:read', 'Read scheduled jobs'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'job:read');
INSERT INTO sys_permission (code, name)
SELECT 'job:write', 'Manage scheduled jobs'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'job:write');
INSERT INTO sys_permission (code, name)
SELECT 'file:read', 'Download files'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'file:read');
INSERT INTO sys_permission (code, name)
SELECT 'file:write', 'Upload files'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'file:write');
INSERT INTO sys_permission (code, name)
SELECT 'profile:read', 'Read own profile'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'profile:read');
INSERT INTO sys_permission (code, name)
SELECT 'profile:write', 'Manage own profile'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'profile:write');
INSERT INTO sys_permission (code, name)
SELECT 'notice:read', 'Read managed notices'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'notice:read');
INSERT INTO sys_permission (code, name)
SELECT 'notice:write', 'Manage notices'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'notice:write');

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
CROSS JOIN sys_permission p
WHERE r.code = 'ADMIN'
  AND p.code IN (
    'menu:read', 'menu:write',
    'job:read', 'job:write',
    'file:read', 'file:write',
    'profile:read', 'profile:write',
    'notice:read', 'notice:write'
  );

-- 保留普通用户原有的菜单、文件和个人资料访问范围，不授予管理写操作。
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
CROSS JOIN sys_permission p
WHERE r.code = 'USER'
  AND p.code IN ('menu:read', 'file:read', 'file:write', 'profile:read', 'profile:write');
