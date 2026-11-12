-- 登出只撤销当前会话，和管理员撤销其他会话使用不同权限码。
INSERT INTO sys_permission (code, name)
SELECT 'session:logout', 'Logout current session'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'session:logout');

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
JOIN sys_permission p ON p.code = 'session:logout'
WHERE r.code IN ('USER', 'ADMIN');
