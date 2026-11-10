CREATE TABLE IF NOT EXISTS sys_dept (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  parent_id BIGINT NULL,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_dept_parent FOREIGN KEY (parent_id) REFERENCES sys_dept(id) ON DELETE RESTRICT
);
CREATE INDEX idx_dept_parent_sort ON sys_dept(parent_id, sort_order, id);

INSERT INTO sys_dept (parent_id, code, name, sort_order)
SELECT NULL, 'ROOT', 'Default Organization', 0
WHERE NOT EXISTS (SELECT 1 FROM sys_dept WHERE code = 'ROOT');
