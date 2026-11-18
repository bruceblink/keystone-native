package app.keystone.user;

/** 标记用户名唯一约束冲突，供用户导入逐行映射专用错误码。 */
public final class UsernameAlreadyExistsException extends IllegalArgumentException {
    public UsernameAlreadyExistsException(Throwable cause) {
        super("username already exists", cause);
    }
}
