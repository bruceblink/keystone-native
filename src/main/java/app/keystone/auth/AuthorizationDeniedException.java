package app.keystone.auth;

/** 服务层授权失败的结构化异常，保证绕过 REST 入口时仍使用统一错误分类。 */
public final class AuthorizationDeniedException extends RuntimeException {
    private final String code;
    private final int status;

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
