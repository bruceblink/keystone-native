package app.keystone.auth;

import app.keystone.ErrorCode;

/** 服务层授权失败的结构化异常，保证绕过 REST 入口时仍使用统一错误分类。 */
public final class AuthorizationDeniedException extends RuntimeException {
    private final String code;
    private final int status;

    public AuthorizationDeniedException(ErrorCode code, String message) {
        this(code.code(), code.httpStatus(), message);
    }

    /** 兼容外部扩展；新业务分支应使用 ErrorCode 构造函数。 */
    @Deprecated
    public AuthorizationDeniedException(String code, int status, String message) {
        super(message);
        this.code = code;
        this.status = status;
    }

    public String code() {
        return code;
    }

    public int status() {
        return status;
    }
}
