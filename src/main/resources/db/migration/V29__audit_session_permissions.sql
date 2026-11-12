INSERT INTO sys_permission (code, name)
SELECT 'session:read', 'Read active sessions'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'session:read');
INSERT INTO sys_permission (code, name)
SELECT 'session:revoke', 'Revoke sessions'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'session:revoke');
INSERT INTO sys_permission (code, name)
SELECT 'audit:read', 'Read audit logs'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'audit:read');
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id FROM sys_role r CROSS JOIN sys_permission p
WHERE r.code = 'ADMIN' AND p.code IN ('session:read', 'session:revoke', 'audit:read');
