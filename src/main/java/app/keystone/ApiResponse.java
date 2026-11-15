package app.keystone;

/**
 * 新 API 的统一响应结构。
 * error.code 使用 {@link ErrorCode} 目录中的稳定业务错误码，message 只用于可读说明。
 */
public record ApiResponse<T>(boolean success, T data, String message, java.util.Map<String, String> error) {
    public ApiResponse(boolean success, T data, String message) {
        this(success, data, message, success ? null : java.util.Map.of("code", ErrorCode.VALIDATION_FAILED.code()));
    }

    public ApiResponse(boolean success, T data, String message, ErrorCode errorCode) {
        this(success, data, message, success ? null : java.util.Map.of("code", errorCode.code()));
    }

    public ApiResponse(boolean success, T data, String message, String errorCode) {
        this(success, data, message, success ? null : java.util.Map.of("code", normalizeError(errorCode)));
    }

    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, data, "OK", (java.util.Map<String, String>) null);
    }

    /** 兼容未迁移的参数校验入口；新业务分支必须显式传入 ErrorCode。 */
    @Deprecated
    public static <T> ApiResponse<T> error(String message) {
        return error(ErrorCode.VALIDATION_FAILED, message);
    }

    public static <T> ApiResponse<T> error(ErrorCode errorCode, String message) {
        return new ApiResponse<>(false, null, message, errorCode);
    }

    public static <T> ApiResponse<T> error(String error, String message) {
        return new ApiResponse<>(false, null, message, ErrorCode.fromCode(error));
    }

    /** 生成带统一 JSON 错误体的 JAX-RS 响应，保留调用方传入的 HTTP 状态。 */
    public static jakarta.ws.rs.core.Response response(int status, ErrorCode errorCode, String message) {
        return jakarta.ws.rs.core.Response.status(status).entity(error(errorCode, message)).build();
    }

    /** 保留字符串代码入口，未知代码统一降级为 validation_failed。 */
    public static jakarta.ws.rs.core.Response response(int status, String error, String message) {
        return response(status, ErrorCode.fromCode(error), message);
    }

    private static String normalizeError(String error) {
        return ErrorCode.fromCode(error).code();
    }
}
