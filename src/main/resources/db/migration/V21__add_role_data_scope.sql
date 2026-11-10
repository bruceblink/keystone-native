ALTER TABLE sys_role
  ADD COLUMN data_scope VARCHAR(32) NOT NULL DEFAULT 'ALL' AFTER enabled,
  ADD COLUMN dept_scope TEXT NULL AFTER data_scope;
