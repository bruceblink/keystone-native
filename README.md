# Keystone Native

Keystone 的独立 Quarkus Native 重实现，首阶段以 **Quarkus REST + JDBC + MySQL + Flyway + SmallRye JWT** 为基础。它与原有 Spring Boot 工程并行演进，不修改原项目。

## 当前垂直切片

- `GET /api/v1/health`：无数据库依赖的健康检查
- `POST /api/v1/auth/login`：数据库用户认证，返回 HS256 JWT
- `GET /api/v1/users?page=1&size=20`：JWT 保护的用户分页查询
- `/api/openapi`、`/api/swagger`：OpenAPI 与 Swagger UI
- 启动时由 Flyway 创建 `sys_user` 并写入开发用 `admin/password` 用户

API 响应统一为 `{ "success": true, "data": ..., "message": "OK" }`，便于后续对齐 Keystone 原接口契约。

## 本地运行

需要 JDK 21+ 和 Docker（用于 MySQL）。项目使用 Gradle Wrapper，无需预装 Gradle。先启动 MySQL：

```bash
docker compose up -d mysql
./gradlew quarkusDev
```

然后访问 `http://localhost:8080/api/v1/health`。登录示例：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"password"}'
```

开发环境默认密钥仅用于本地验证，部署时必须设置 `JWT_SECRET`（至少 32 字符）以及 `DB_URL`、`DB_USERNAME`、`DB_PASSWORD`。

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

## 后续切片

按依赖关系继续实现角色/权限、部门、字典、会话刷新、操作日志和任务管理；每个切片先建立 HTTP 契约测试，再接入迁移脚本。旧 Keystone 的数据迁移脚本放在 `src/main/resources/db/migration`，通过双写或停机窗口完成平滑切换。
