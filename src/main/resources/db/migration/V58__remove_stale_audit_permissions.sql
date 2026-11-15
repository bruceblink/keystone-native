-- 删除没有对应管理接口的审计权限标识；已有角色和菜单关联由外键级联清理。
DELETE FROM sys_permission
WHERE code IN ('audit:delete', 'audit:export');
