# V63 菜单权限目录升级

V63 在 `sys_permission` 增加 `status` 和 `deprecated`，并把 `sys_menu.permission` 中已有的有效标识补入 `sys_menu_permission`。旧字符串列继续保留为兼容镜像。运行时以关系表为读取来源。

迁移不会删除菜单权限关系。迁移发现一个菜单有多条关系、旧标识不在权限目录，或旧字符串与现有关联不一致时，会在修改表结构前失败。MySQL 错误只显示对应检查约束名，不会显示菜单 ID。执行迁移前，可用下面的只读查询定位记录。

## 定位迁移冲突

一个菜单存在多条权限关联：

```sql
SELECT BIN_TO_UUID(menu.id, 0) AS menu_id,
       menu.code,
       COUNT(*) AS permission_count,
       GROUP_CONCAT(permission.code ORDER BY permission.code) AS permissions
FROM sys_menu AS menu
JOIN sys_menu_permission AS link ON link.menu_id = menu.id
JOIN sys_permission AS permission ON permission.id = link.permission_id
GROUP BY menu.id, menu.code
HAVING COUNT(*) > 1;
```

旧字符串不在当前权限目录：

```sql
SELECT BIN_TO_UUID(menu.id, 0) AS menu_id,
       menu.code,
       menu.permission
FROM sys_menu AS menu
LEFT JOIN sys_permission AS permission
  ON CAST(permission.code AS BINARY) = CAST(TRIM(menu.permission) AS BINARY)
WHERE menu.permission IS NOT NULL
  AND TRIM(menu.permission) <> ''
  AND permission.id IS NULL;
```

旧字符串和已有关系指向不同权限：

```sql
SELECT BIN_TO_UUID(menu.id, 0) AS menu_id,
       menu.code,
       menu.permission AS legacy_permission,
       permission.code AS linked_permission
FROM sys_menu AS menu
JOIN sys_menu_permission AS link ON link.menu_id = menu.id
JOIN sys_permission AS permission ON permission.id = link.permission_id
WHERE menu.permission IS NOT NULL
  AND TRIM(menu.permission) <> ''
  AND CAST(TRIM(menu.permission) AS BINARY) <> CAST(permission.code AS BINARY);
```

## 修复失败迁移

先根据查询结果确认每个菜单应保留的权限。不要批量删除关系或用旧字符串覆盖关系。修正冲突后，检查 `flyway_schema_history` 中是否存在失败的 V63 记录：

```sql
SELECT installed_rank, version, description, success
FROM flyway_schema_history
WHERE version = '63';
```

如果记录显示 `success = 0`，使用与应用相同的数据库连接配置执行 Flyway `repair`，再启动 Native 让 V63 重跑：

```sh
FLYWAY_URL="$DB_URL" \
FLYWAY_USER="$DB_USERNAME" \
FLYWAY_PASSWORD="$DB_PASSWORD" \
flyway repair
```

V63 的每个列变更都会先查 `information_schema`。关联回填只插入缺失行；镜像回填只填空值或规范化同一标识。因此，权限检查通过后即使迁移在后续语句中断，修复 Flyway 失败记录并重跑也不会覆盖已有关系。
