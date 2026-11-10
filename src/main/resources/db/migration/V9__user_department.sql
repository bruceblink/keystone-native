ALTER TABLE sys_user ADD COLUMN dept_id BIGINT NULL;
ALTER TABLE sys_user ADD CONSTRAINT fk_user_dept FOREIGN KEY (dept_id) REFERENCES sys_dept(id) ON DELETE SET NULL;
CREATE INDEX idx_user_dept ON sys_user(dept_id);
