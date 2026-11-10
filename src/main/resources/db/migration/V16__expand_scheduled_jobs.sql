ALTER TABLE sys_job
  ADD COLUMN job_group VARCHAR(64) NOT NULL DEFAULT 'DEFAULT' AFTER name,
  ADD COLUMN invoke_target VARCHAR(255) NOT NULL DEFAULT 'keystoneJob.heartbeat()' AFTER job_group,
  ADD COLUMN job_params TEXT NULL AFTER invoke_target,
  ADD COLUMN concurrent BOOLEAN NOT NULL DEFAULT TRUE AFTER job_params,
  ADD COLUMN remark VARCHAR(255) NULL AFTER concurrent;
