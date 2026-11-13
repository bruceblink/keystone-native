# Keystone Native

Keystone 的独立 Quarkus Native 重实现，使用 **Quarkus 3.40.1 + Gradle + GraalVM JDK 25 + MySQL + Flyway + SmallRye JWT（RS256）**。项目与原有 Spring Boot 工程并行演进，不修改原项目。

## 已实现功能

- `GET /api/v1/health`：无数据库依赖的健康检查
- `POST /api/v1/auth/login`、`POST /api/v1/auth/refresh`、`POST /api/v1/auth/logout`
- `POST /api/v1/auth/change-initial-password`：首次登录前修改初始管理员密码
- 用户、角色、部门、菜单和权限管理，包含下拉树和兼容旧 Keystone 的接口
- 字典类型与字典项、系统配置、操作日志、动态 Cron 任务
- 通知、岗位、个人资料和密码修改
- 在线会话、登录审计、服务器信息和强制下线
- 文件上传、批量上传和安全下载
- 原 Keystone `/system/*`、`/logs/*`、`/monitor/*` 兼容路由，以及 CSV 导出/用户导入入口
- `/api/openapi`、`/api/swagger`：OpenAPI 文档和 Swagger UI

API 响应统一为 `{ "success": true, "data": ..., "message": "OK" }`，便于对齐原 Keystone 接口契约。

Flyway 会在新数据库中创建初始 `admin/password` 账户，并将其标记为必须修改密码。该凭据仅用于首次初始化，首次使用时先调用：

```bash
curl -X POST http://localhost:8080/api/v1/auth/change-initial-password \
  -H 'content-type: application/json' \
  -d '{"username":"admin","currentPassword":"password","newPassword":"replace-with-a-strong-password"}'
```

生产环境必须通过 `JWT_PRIVATE_KEY_LOCATION` 提供签名私钥，通过 `JWT_PUBLIC_KEY_LOCATION` 提供当前外部 RSA 公钥，并通过 `JWT_KEY_ID` 提供当前签名密钥的标识。启用重叠密钥时，还必须通过 `JWT_VERIFY_PUBLIC_KEY_LOCATION` 指向包含全部公钥的 JWK Set 文件或 HTTPS JWK Set URL。应用没有内置生产公钥回退；缺少外部公钥或密钥标识时，令牌验证或签发会失败。

## 本地运行

需要 GraalVM JDK 25 和 Docker（用于 MySQL）。项目使用 Gradle Wrapper，无需预装 Gradle。

```bash
docker compose up -d mysql

# 本地开发使用测试密钥；不要用于生产环境
export JWT_PRIVATE_KEY_LOCATION="file://${PWD}/src/test/resources/keys/privateKey.pem"
export JWT_PUBLIC_KEY_LOCATION="file://${PWD}/src/test/resources/keys/publicKey.pem"
export JWT_KEY_ID="test-rs256-1"

./gradlew quarkusDev
```

健康检查地址：<http://localhost:8080/api/v1/health>。

运行测试：

```bash
./gradlew test
```

如果机器上的 `JAVA_HOME` 不是完整 JDK，请先指向带有 `javac` 的 JDK。Gradle 会自动读取 `HTTPS_PROXY`/`https_proxy` 并配置依赖下载代理。

## JVM 构建

默认构建产物是 Quarkus fast-jar，需要保留整个 `build/quarkus-app` 目录：

```bash
./gradlew quarkusBuild -x test
java -jar build/quarkus-app/quarkus-run.jar
```

`quarkus-run.jar` 是启动器，fast-jar 的实际大小应按整个 `build/quarkus-app` 目录计算。

也可以生成单文件 uber-jar：

```bash
./gradlew quarkusBuild -x test -Dquarkus.package.jar.type=uber-jar
java -jar build/keystone-native-0.1.0-SNAPSHOT-runner.jar
```

## Native 构建

本机安装 GraalVM/Mandrel 后：

```bash
./gradlew nativeBuild -x test
./build/keystone-native-0.1.0-SNAPSHOT-runner
```

或使用容器构建：

```bash
docker build -t keystone-native:native .
```

GitHub Actions 在每次推送和 Pull Request 中执行 MySQL 集成测试、JVM 打包，并通过 Mandrel Builder 构建 Native 容器镜像。Native 镜像使用 `Dockerfile` 的多阶段构建，不需要在开发机安装 GraalVM。

## 构建产物与性能基准

以下数据来自当前项目的本地构建，用于比较 JVM 和 Native 的部署开销。镜像基础层、依赖版本和构建环境变化后，数值会随之变化。

| 指标 | Spring Boot Keystone 基线 | Quarkus JVM | Quarkus Native |
|---|---:|---:|---:|
| 应用包 | 可执行 JAR **95.6 MB** | fast-jar 目录 **31,175,407 bytes**（约 29.73 MiB）；uber-jar **30,921,462 bytes**（约 29.49 MiB） | Native runner **71,436,608 bytes**（约 68.13 MiB） |
| Docker 本地镜像 | 未在本次基准中测量 | **350,939,929 bytes**（约 334.68 MiB；`docker images` 显示 351 MB） | **169,936,439 bytes**（约 162.06 MiB；`docker images` 显示 170 MB） |
| `docker save` + gzip | 未在本次基准中测量 | **139,045,709 bytes**（约 132.60 MiB） | **63,461,403 bytes**（约 60.52 MiB） |
| Native 启动日志 | — | — | 约 **0.089 秒** |
| Native 进程 RSS | — | — | 约 **57.6 MB** |
| Native 构建开销 | — | — | 约 **5 分 22 秒**；峰值构建 RSS 约 **3.37 GB** |

指标口径：

- `docker image inspect .Size` 是镜像层解压后的本地占用，不是 registry 传输大小。
- `docker save | gzip` 是压缩后的传输归档大小，不代表容器运行时占用。
- `MiB` 使用 `1 MiB = 1,048,576 bytes`；Docker 的 `MB` 显示为四舍五入后的展示值。
- JVM 构建和测试统一使用 GraalVM JDK 25；Native 镜像使用 `Dockerfile` 中固定 digest 的 Quarkus Micro Image。
- Native 镜像大小按当前 runner 与固定 digest 的运行时镜像层实测；完整多阶段 Docker 构建需要向 Docker BuildKit 提供 `proxy-ca` secret（如使用代理环境）。
- Spring Boot 的 95.6 MB 是原 Keystone 的可执行 Fat JAR，用作参考基线，不是本仓库生成的产物。

## 配置与密钥

开发和部署时设置以下环境变量：

```text
DB_URL
DB_USERNAME
DB_PASSWORD
JWT_PRIVATE_KEY_LOCATION
JWT_PUBLIC_KEY_LOCATION
JWT_VERIFY_PUBLIC_KEY_LOCATION（可选；配置重叠 JWT 公钥时必填，指向 JWK Set 文件或 HTTPS JWK Set URL）
JWT_KEY_ID
JWT_JWK_CACHE_SECONDS（可选，默认 60，范围 1-3600）
JWT_JWK_KEYS（可选，默认 `none`；使用 `old-kid=旧公钥位置;another-kid=另一公钥位置` 发布重叠 JWK）
TRUSTED_PROXY_CIDRS（可选，逗号分隔的受信反向代理 CIDR；为空时忽略 X-Forwarded-For）
JWT_ISSUER（可选，默认 keystone-native）
JWT_AUDIENCE（可选，默认 keystone-api）
```

使用 Compose 前，将部署密钥放入 `docker/keys/privateKey.pem` 和 `docker/keys/publicKey.pem`；这些文件不会提交到 Git。
