package app.keystone.role;

/** 内置系统角色受保护，不能通过角色管理接口删除。 */
public final class ProtectedSystemRoleException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ProtectedSystemRoleException() {
        super("built-in administrator role is protected");
    }
}
