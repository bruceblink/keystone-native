-- 任务最近执行时间使用微秒精度，匹配执行日志和 Phoenix 的时间字段。
-- 已经达到目标精度时不执行 DDL，支持迁移部分执行后的安全重跑。
SET @job_run_time_precision = (
  SELECT DATETIME_PRECISION
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'sys_job'
    AND column_name = 'last_run_at'
);

SET @job_run_time_upgrade = CASE
  WHEN @job_run_time_precision IS NULL OR @job_run_time_precision < 6
    THEN 'ALTER TABLE sys_job MODIFY COLUMN last_run_at TIMESTAMP(6) NULL'
  ELSE 'SELECT 1'
END;

PREPARE stmt FROM @job_run_time_upgrade;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
