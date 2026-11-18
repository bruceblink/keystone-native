-- 为权限目录补充启用和废弃状态，并将菜单旧字段校正为关系表的兼容镜像。
-- Phoenix 的菜单编辑接口是单值；多条关联或新旧值冲突时停止迁移，要求先人工确认数据。
CREATE TEMPORARY TABLE keystone_v63_menu_permission_guard (
  no_multiple_links TINYINT NOT NULL,
  no_unknown_legacy_code TINYINT NOT NULL,
  no_legacy_link_mismatch TINYINT NOT NULL,
  CONSTRAINT ck_v63_menu_permission_single CHECK (no_multiple_links = 1),
  CONSTRAINT ck_v63_menu_permission_catalog CHECK (no_unknown_legacy_code = 1),
  CONSTRAINT ck_v63_menu_permission_match CHECK (no_legacy_link_mismatch = 1)
) ENGINE=InnoDB;

INSERT INTO keystone_v63_menu_permission_guard
SELECT
  IF(NOT EXISTS (
    SELECT menu_id FROM sys_menu_permission GROUP BY menu_id HAVING COUNT(*) > 1
  ), 1, 0),
  IF(NOT EXISTS (
    SELECT 1
    FROM sys_menu menu
    LEFT JOIN sys_permission permission
      ON CAST(permission.code AS BINARY) = CAST(TRIM(menu.permission) AS BINARY)
    WHERE menu.permission IS NOT NULL
      AND TRIM(menu.permission) <> ''
      AND permission.id IS NULL
  ), 1, 0),
  IF(NOT EXISTS (
    SELECT 1
    FROM sys_menu menu
    JOIN sys_menu_permission menu_permission ON menu_permission.menu_id = menu.id
    JOIN sys_permission permission ON permission.id = menu_permission.permission_id
    WHERE menu.permission IS NOT NULL
      AND TRIM(menu.permission) <> ''
      AND CAST(TRIM(menu.permission) AS BINARY) <> CAST(permission.code AS BINARY)
  ), 1, 0);

DROP TEMPORARY TABLE keystone_v63_menu_permission_guard;

SET @v63_has_permission_status = (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_permission' AND column_name = 'status'
);
SET @v63_add_permission_status = IF(
  @v63_has_permission_status = 0,
  'ALTER TABLE sys_permission ADD COLUMN status TINYINT NOT NULL DEFAULT 1',
  'SELECT 1'
);
PREPARE v63_permission_status_stmt FROM @v63_add_permission_status;
EXECUTE v63_permission_status_stmt;
DEALLOCATE PREPARE v63_permission_status_stmt;

SET @v63_has_permission_deprecated = (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'sys_permission' AND column_name = 'deprecated'
);
SET @v63_add_permission_deprecated = IF(
  @v63_has_permission_deprecated = 0,
  'ALTER TABLE sys_permission ADD COLUMN deprecated TINYINT NOT NULL DEFAULT 0',
  'SELECT 1'
);
PREPARE v63_permission_deprecated_stmt FROM @v63_add_permission_deprecated;
EXECUTE v63_permission_deprecated_stmt;
DEALLOCATE PREPARE v63_permission_deprecated_stmt;

-- 缺失关联只从已登记旧值补入；现有关联不会被更新或删除。
INSERT INTO sys_menu_permission (menu_id, permission_id)
SELECT menu.id, permission.id
FROM sys_menu menu
JOIN sys_permission permission
  ON CAST(permission.code AS BINARY) = CAST(TRIM(menu.permission) AS BINARY)
LEFT JOIN sys_menu_permission menu_permission ON menu_permission.menu_id = menu.id
WHERE menu.permission IS NOT NULL
  AND TRIM(menu.permission) <> ''
  AND menu_permission.menu_id IS NULL;

-- 关系表是读取来源；兼容旧字段只在空值时补成关系码，避免覆盖冲突数据。
UPDATE sys_menu menu
JOIN sys_menu_permission menu_permission ON menu_permission.menu_id = menu.id
JOIN sys_permission permission
  ON permission.id = menu_permission.permission_id AND permission.status = 1
SET menu.permission = permission.code
WHERE menu.permission IS NULL OR TRIM(menu.permission) = '';

UPDATE sys_menu menu
JOIN sys_menu_permission menu_permission ON menu_permission.menu_id = menu.id
JOIN sys_permission permission
  ON permission.id = menu_permission.permission_id AND permission.status = 1
SET menu.permission = permission.code
WHERE menu.permission IS NOT NULL
  AND CAST(TRIM(menu.permission) AS BINARY) = CAST(permission.code AS BINARY)
  AND CAST(menu.permission AS BINARY) <> CAST(permission.code AS BINARY);
