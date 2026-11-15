-- 删除不再公开的审计日志删除权限；读取和导出权限继续保留。
-- sys_role_permission 与 sys_menu_permission 使用 ON DELETE CASCADE，删除权限目录项时同步清理关联授权。
DELETE FROM sys_permission
WHERE code IN ('login-log:delete', 'operation-log:delete');
