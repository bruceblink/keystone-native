-- 一次性重建公告、配置和字典身份表。
-- 应用层生成 UUIDv7；固定启动数据使用 UUIDv5。MySQL 使用 BINARY(16)，SQL 边界使用
-- UUID_TO_BIN(..., 0) 和 BIN_TO_UUID(..., 0)。旧整数数据属于一次性系统初始化数据。

SET @create_content_marker = (SELECT IF(COUNT(*) = 0,
  'CREATE TABLE sys_uuid_content_migration (migration_key VARCHAR(64) PRIMARY KEY, completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)',
  'DO 0')
  FROM information_schema.tables
  WHERE table_schema = DATABASE() AND table_name = 'sys_uuid_content_migration');
PREPARE stmt FROM @create_content_marker; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @uuid_content_should_rebuild = (SELECT IF(COUNT(*) = 0, 1, 0)
  FROM sys_uuid_content_migration WHERE migration_key = 'V48_CONTENT_IDENTITY');

SET FOREIGN_KEY_CHECKS = 0;
SET @drop_content_0 = IF(@uuid_content_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_dict_item', 'DO 0');
PREPARE stmt FROM @drop_content_0; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_content_1 = IF(@uuid_content_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_dict_type', 'DO 0');
PREPARE stmt FROM @drop_content_1; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_content_2 = IF(@uuid_content_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_notice', 'DO 0');
PREPARE stmt FROM @drop_content_2; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @drop_content_3 = IF(@uuid_content_should_rebuild = 1, 'DROP TABLE IF EXISTS sys_config', 'DO 0');
PREPARE stmt FROM @drop_content_3; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE IF NOT EXISTS sys_config (
  id BINARY(16) PRIMARY KEY,
  config_key VARCHAR(128) NOT NULL UNIQUE,
  config_value VARCHAR(2000) NOT NULL,
  description VARCHAR(255) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sys_notice (
  id BINARY(16) PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  content TEXT NOT NULL,
  notice_type VARCHAR(32) NOT NULL DEFAULT 'NOTICE',
  published BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  publish_at TIMESTAMP NULL,
  created_by VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
SET @create_notice_index = (SELECT IF(COUNT(*) = 0,
  'CREATE INDEX idx_notice_public ON sys_notice(published, enabled, publish_at, id)',
  'DO 0')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_notice' AND index_name = 'idx_notice_public');
PREPARE stmt FROM @create_notice_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS sys_dict_type (
  id BINARY(16) PRIMARY KEY,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(128) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sys_dict_item (
  id BINARY(16) PRIMARY KEY,
  type_id BINARY(16) NOT NULL,
  item_value VARCHAR(128) NOT NULL,
  item_label VARCHAR(128) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT fk_dict_item_type_uuid FOREIGN KEY (type_id) REFERENCES sys_dict_type(id) ON DELETE CASCADE,
  CONSTRAINT uq_dict_item_value_uuid UNIQUE (type_id, item_value)
);
SET @create_dict_index = (SELECT IF(COUNT(*) = 0,
  'CREATE INDEX idx_dict_item_type_sort_uuid ON sys_dict_item(type_id, sort_order, id)',
  'DO 0')
  FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'sys_dict_item' AND index_name = 'idx_dict_item_type_sort_uuid');
PREPARE stmt FROM @create_dict_index; EXECUTE stmt; DEALLOCATE PREPARE stmt;

INSERT IGNORE INTO sys_config (id, config_key, config_value, description)
VALUES
  (UUID_TO_BIN('019c04fd-d5da-56de-977d-601ec553266b', 0), 'site.name', 'Keystone', '系统名称'),
  (UUID_TO_BIN('5be4dc06-0a3f-5d2e-b670-fb42b5904717', 0), 'site.url', '/', '系统访问路径');

INSERT IGNORE INTO sys_dict_type (id, code, name)
VALUES
  (UUID_TO_BIN('86809ca8-7fe0-5a42-8d31-9d4875c8d0ee', 0), 'notice', '公告类型'),
  (UUID_TO_BIN('be091fe7-7f64-5947-b988-92af9b0964e5', 0), 'yes-no', '是否');

INSERT IGNORE INTO sys_dict_item (id, type_id, item_value, item_label, sort_order)
VALUES
  (UUID_TO_BIN('c4cb6989-bc40-5749-9d3d-06fbec367421', 0), UUID_TO_BIN('86809ca8-7fe0-5a42-8d31-9d4875c8d0ee', 0), 'NOTICE', '通知', 1),
  (UUID_TO_BIN('ad0ee72b-e6e7-5e12-867d-38eaae4191ca', 0), UUID_TO_BIN('86809ca8-7fe0-5a42-8d31-9d4875c8d0ee', 0), 'WARNING', '警告', 2),
  (UUID_TO_BIN('b6e456c6-bdc4-5d5c-9868-1aa15e5c6d5b', 0), UUID_TO_BIN('be091fe7-7f64-5947-b988-92af9b0964e5', 0), '1', '是', 1),
  (UUID_TO_BIN('5d8cb775-8d31-504a-a848-0ce01bd9f120', 0), UUID_TO_BIN('be091fe7-7f64-5947-b988-92af9b0964e5', 0), '0', '否', 2);

INSERT IGNORE INTO sys_notice (id, title, content, notice_type, published, enabled, created_by)
VALUES (UUID_TO_BIN('028879b6-648e-5a11-b767-a785079983ea', 0), '系统公告', 'Keystone 管理平台已完成初始化。', 'NOTICE', TRUE, TRUE, 'system');

-- 读取边界使用 BIN_TO_UUID；应用接口只返回规范小写字符串。
SET @uuid_content_first_config = (SELECT BIN_TO_UUID(id, 0) FROM sys_config ORDER BY id LIMIT 1);
INSERT IGNORE INTO sys_uuid_content_migration (migration_key)
VALUES ('V48_CONTENT_IDENTITY');
