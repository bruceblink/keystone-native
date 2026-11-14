-- 为公告和计划任务补充可验证的所有者字段。
-- 旧记录保留 NULL；NULL 记录只能由 ALL/TENANT 范围主体读取。
-- 使用 information_schema 保护重复执行和部分执行后的重跑。

SET @add_notice_owner = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_notice ADD COLUMN owner_id BINARY(16) NULL AFTER created_by',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_notice' AND column_name = 'owner_id');
PREPARE stmt FROM @add_notice_owner; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_notice_owner_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_notice ADD INDEX idx_notice_owner_time (owner_id, created_at, id)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_notice' AND index_name = 'idx_notice_owner_time');
PREPARE stmt FROM @add_notice_owner_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_notice_owner_fk = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_notice ADD CONSTRAINT fk_notice_owner FOREIGN KEY (owner_id) REFERENCES sys_user(id) ON DELETE SET NULL',
  'SELECT 1')
  FROM information_schema.table_constraints
  WHERE table_schema = DATABASE() AND table_name = 'sys_notice' AND constraint_name = 'fk_notice_owner');
PREPARE stmt FROM @add_notice_owner_fk; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_job_owner = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_job ADD COLUMN created_by BINARY(16) NULL AFTER remark',
  'SELECT 1')
  FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_job' AND column_name = 'created_by');
PREPARE stmt FROM @add_job_owner; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_job_owner_index = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_job ADD INDEX idx_job_created_by (created_by, id)',
  'SELECT 1')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_job' AND index_name = 'idx_job_created_by');
PREPARE stmt FROM @add_job_owner_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @add_job_owner_fk = (SELECT IF(COUNT(*) = 0,
  'ALTER TABLE sys_job ADD CONSTRAINT fk_job_created_by FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE SET NULL',
  'SELECT 1')
  FROM information_schema.table_constraints
  WHERE table_schema = DATABASE() AND table_name = 'sys_job' AND constraint_name = 'fk_job_created_by');
PREPARE stmt FROM @add_job_owner_fk; EXECUTE stmt; DEALLOCATE PREPARE stmt;
