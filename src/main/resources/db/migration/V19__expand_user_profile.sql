ALTER TABLE sys_user
  ADD COLUMN post_id BIGINT NULL AFTER dept_id,
  ADD COLUMN email VARCHAR(128) NULL AFTER display_name,
  ADD COLUMN phone_number VARCHAR(32) NULL AFTER email,
  ADD COLUMN sex TINYINT NULL AFTER phone_number,
  ADD COLUMN avatar VARCHAR(512) NULL AFTER sex,
  ADD COLUMN login_ip VARCHAR(64) NULL AFTER enabled,
  ADD COLUMN login_at TIMESTAMP NULL AFTER login_ip,
  ADD COLUMN remark VARCHAR(500) NULL AFTER login_at;

CREATE INDEX idx_sys_user_post ON sys_user(post_id);
CREATE INDEX idx_sys_user_phone ON sys_user(phone_number);
