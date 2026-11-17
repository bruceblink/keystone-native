package app.keystone.auth;

import app.keystone.ErrorCode;

/** 保存 API Key 签发字段错误，使资源入口能返回对应的业务错误码。 */
public final class ApiKeyIssueValidationException extends IllegalArgumentException {
    private final ErrorCode errorCode;

    public ApiKeyIssueValidationException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
