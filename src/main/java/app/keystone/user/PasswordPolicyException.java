package app.keystone.user;

import app.keystone.ErrorCode;

/** 保留密码策略的具体失败原因，异常文本不包含密码或策略配置内容。 */
public final class PasswordPolicyException extends IllegalArgumentException {
    private final ErrorCode errorCode;

    public PasswordPolicyException(ErrorCode errorCode) {
        super("password does not meet security policy");
        this.errorCode = java.util.Objects.requireNonNull(errorCode, "errorCode");
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
