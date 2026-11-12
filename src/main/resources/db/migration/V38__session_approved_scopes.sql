-- 刷新会话保存创建时批准的权限范围，后续刷新不得扩大范围。
SET @add_approved_scope = (SELECT IF(COUNT(*) = 0, 'ALTER TABLE sys_auth_session ADD COLUMN approved_scope TEXT NULL AFTER client_id', 'SELECT 1') FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'sys_auth_session' AND column_name = 'approved_scope');
PREPARE stmt FROM @add_approved_scope; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE sys_auth_session s
JOIN (
  SELECT ur.user_id, GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ' ') AS scopes
  FROM sys_user_role ur
  JOIN sys_role r ON r.id = ur.role_id AND r.enabled = true
  JOIN sys_role_permission rp ON rp.role_id = r.id
  JOIN sys_permission p ON p.id = rp.permission_id
  GROUP BY ur.user_id
) current_permissions ON current_permissions.user_id = s.user_id
SET s.approved_scope = current_permissions.scopes
WHERE s.approved_scope IS NULL;
