# Keystone Native

Keystone 的独立 Quarkus Native 重实现，首阶段以 **Quarkus REST + JDBC + MySQL + Flyway + SmallRye JWT** 为基础。它与原有 Spring Boot 工程并行演进，不修改原项目。

## 当前垂直切片

- `GET /api/v1/health`：无数据库依赖的健康检查
- `POST /api/v1/auth/login`：数据库用户认证，返回 HS256 JWT
- `GET /api/v1/users?page=1&size=20`：JWT 保护的用户分页查询
- `POST /api/v1/auth/refresh`、`POST /api/v1/auth/logout`：Refresh Token 轮换与注销
- `GET/POST/PUT/DELETE /api/v1/users`：管理员用户 CRUD 与角色分配
- `GET /api/v1/roles`、`GET/POST/PUT/DELETE /api/v1/departments`：角色权限和部门树
- `GET/POST/PUT/DELETE /api/v1/menus`：角色菜单权限树
- `GET/POST /api/v1/dictionaries`：字典类型与字典项管理
- `GET/POST/PUT/DELETE /api/v1/configs`：系统配置管理
- `GET /api/v1/operation-logs`：管理员操作日志分页查询
- `GET/POST/PUT/DELETE /api/v1/jobs`、`POST /api/v1/jobs/{id}/trigger`：动态 Cron 任务
- `/api/openapi`、`/api/swagger`：OpenAPI 与 Swagger UI
- 启动时由 Flyway 创建 `sys_user` 并写入开发用 `admin/password` 用户

API 响应统一为 `{ "success": true, "data": ..., "message": "OK" }`，便于后续对齐 Keystone 原接口契约。

## 本地运行

需要 JDK 21+ 和 Docker（用于 MySQL）。项目使用 Gradle Wrapper，无需预装 Gradle。先启动 MySQL：

```bash
docker compose up -d mysql
./gradlew quarkusDev
```

如果机器上的 `JAVA_HOME` 不是完整 JDK，请先指向带有 `javac` 的 JDK。Gradle 会自动读取 `HTTPS_PROXY`/`https_proxy` 并配置依赖下载代理。

然后访问 `http://localhost:8080/api/v1/health`。登录示例：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"password"}'
```

开发环境使用仓库内的 RSA 密钥对，部署时应通过 `JWT_PRIVATE_KEY_LOCATION` 和 `JWT_PUBLIC_KEY_LOCATION` 指向外部密钥，并设置 `DB_URL`、`DB_USERNAME`、`DB_PASSWORD`。

## Native 构建

本机安装 GraalVM/Mandrel 后：

```bash
./gradlew nativeBuild -x test
./build/keystone-native-0.1.0-SNAPSHOT-runner
```

或使用容器构建：

```bash
docker build -t keystone-native .
```

GitHub Actions 在每次推送和 Pull Request 中执行 MySQL 集成测试、JVM 打包，并通过 Mandrel Builder 构建 Native 容器镜像。Native 镜像使用 `Dockerfile` 的多阶段构建，不需要在开发机安装 GraalVM。

## 后续切片

按依赖关系继续实现角色/权限、部门、字典、会话刷新、操作日志和任务管理；每个切片先建立 HTTP 契约测试，再接入迁移脚本。旧 Keystone 的数据迁移脚本放在 `src/main/resources/db/migration`，通过双写或停机窗口完成平滑切换。
