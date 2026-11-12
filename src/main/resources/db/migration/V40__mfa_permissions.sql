-- MFA enrollment 和策略变更使用独立权限；API Key 不继承该权限的执行能力。
INSERT INTO sys_permission (code, name)
SELECT 'mfa:manage', 'Manage MFA enrollment and policy'
WHERE NOT EXISTS (SELECT 1 FROM sys_permission WHERE code = 'mfa:manage');

INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
JOIN sys_permission p ON p.code = 'mfa:manage'
WHERE r.code = 'ADMIN';
