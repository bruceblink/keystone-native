INSERT INTO sys_permission (code, name)
SELECT 'role:write', 'Manage roles'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'role:write');
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p
WHERE r.code = 'ADMIN' AND p.code IN ('role:read', 'role:write');
