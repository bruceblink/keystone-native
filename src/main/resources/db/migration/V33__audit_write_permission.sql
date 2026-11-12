-- 兼容日志写入和删除使用独立权限，避免读取权限扩大为审计修改权限。
INSERT INTO sys_permission (code, name)
SELECT 'audit:write', 'Manage audit logs'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'audit:write');

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
JOIN sys_permission p ON p.code = 'audit:write'
WHERE r.code = 'ADMIN';
