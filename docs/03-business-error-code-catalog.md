# Native 业务错误码目录引用

更新日期：2026-11-16。

Native 使用 Phoenix 主目录作为跨项目错误码的唯一可信来源：`keystone-phoenix/docs/11-business-error-code-catalog.md`。Native 不复制另一份业务条件表，只在 `src/main/java/app/keystone/ErrorCode.java` 保存 Java 枚举和反查实现。

## 适用规则

- 服务端代码集合固定为主目录的 21 个代码。`ErrorCode.code()` 是接口返回的稳定字符串。
- `ErrorCode.httpStatus()` 记录默认状态，资源入口仍决定实际 HTTP 状态。替换错误码时保持现有状态，不因为目录反查而改写状态。
- `ErrorCode.find(String)` 是代码到目录项的精确反查入口。它对未知或空值返回空结果；`ErrorCode.fromCode(String)` 和 `ErrorCode.isRegistered(String)` 复用该查找结果，并继续保持现有兼容降级行为。不把可读 `message` 当作代码。
- `RetryAdvice` 只提供调用方处理建议。它不表示任何请求都可以自动重试。
- `authorization_unavailable` 只保留在认证会话、JWK、OIDC、WebAuthn、MFA 状态、权限拦截器和数据范围服务的旧不可用边界。新入口使用更具体的目录代码；迁移时保持原 `503` 状态。

## Native 与主目录的映射

| Native 实现 | 主目录字段 | 验收要求 |
| --- | --- | --- |
| `ErrorCode.code()` | 代码 | 每个代码唯一，且可以反查到一个业务条件 |
| `ErrorCode.httpStatus()` | 默认 HTTP 状态 | 与 Phoenix `ErrorCatalog` 和主目录表格一致 |
| `ErrorCode.meaning()` | 可反查的业务条件 | 说明稳定条件，不复制接口可读提示 |
| `ErrorCode.retryAdvice()` | 处理建议 | 只提供 `never`、`after_correction` 或 `after_backoff` |
| `ErrorCode.messageKey()` | 安全提示键 | 前端可以按键选择语言，不从异常文本猜码 |
| `ErrorCode.safeMessage()` | 提示安全性 | 敏感服务端异常使用固定安全文案 |

Native 的内部异常可以继续使用 Java 异常类型或内部原子结果。资源层、拦截器和异常映射器必须在响应边界选择目录代码，并保留既有 HTTP 状态。

## 静态检查

从三个仓库的父目录运行 Phoenix 提供的无运行时检查：

```sh
python3 keystone-phoenix/scripts/check_error_code_catalog.py \
  --native-root keystone-native \
  --admin-root keystone-admin-web
```

该检查解析 `ErrorCode.java` 的枚举代码和状态，确认 Native 与主目录保持 21 个代码、无重复项、精确反查入口存在。检查通过只证明源码集合和目录元数据一致；它不替代真实 MySQL、HTTP、浏览器或生产代理验收。
