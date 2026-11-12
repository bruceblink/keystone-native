-- 普通用户默认只能访问自己的用户记录；管理员的 ALL 范围保持不变。
UPDATE sys_role
SET data_scope = 'SELF'
WHERE code = 'USER'
  AND (data_scope IS NULL OR data_scope = 'ALL');
