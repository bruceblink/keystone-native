package app.keystone;

/**
 * 新 API 的统一响应结构。
 * error 只返回架构定义的错误分类，message 用于面向调用方的可读说明。
 */
public record ApiResponse<T>(boolean success, T data, String message, java.util.Map<String, String> error) {
    public ApiResponse(boolean success, T data, String message) {
        this(success, data, message, success ? null : classify(message));
    }

    public ApiResponse(boolean success, T data, String message, String errorCode) {
        this(success, data, message, success ? null : java.util.Map.of("code", normalizeError(errorCode)));
    }

    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, data, "OK", (java.util.Map<String, String>) null);
    }

    /** 统一把现有领域消息映射到新错误分类，避免资源入口重复编写分类逻辑。 */
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, null, message, classify(message));
    }

    public static <T> ApiResponse<T> error(String error, String message) {
        return new ApiResponse<>(false, null, message, normalizeError(error));
    }

    /** 生成带统一 JSON 错误体的 JAX-RS 响应。 */
    public static jakarta.ws.rs.core.Response response(int status, String error, String message) {
        return jakarta.ws.rs.core.Response.status(status).entity(error(error, message)).build();
    }

    private static String classify(String message) {
        String value = message == null ? "" : message.toLowerCase(java.util.Locale.ROOT);
        if (value.contains("data scope")) return "data_scope_denied";
        if (value.contains("permission") || value.contains("forbidden")
                || value.contains("cannot issue api keys")) return "permission_denied";
        if (value.contains("session is no longer active") || value.contains("session revoked")) return "session_revoked";
        if (value.contains("unavailable") || value.contains("service is unavailable") || value.contains("state is unavailable")
                || value.contains("token service") || value.contains("jwt key")) return "authorization_unavailable";
        if (value.contains("credential") || value.contains("authentication is required") || value.contains("refresh token")
                || value.contains("mfa challenge") || value.contains("authentication session")) return "invalid_credential";
        return "validation_failed";
    }

    private static String normalizeError(String error) {
        return switch (error) {
            case "invalid_credential", "permission_denied", "data_scope_denied", "session_revoked",
                    "authorization_unavailable", "validation_failed" -> error;
            default -> "validation_failed";
        };
    }
}
