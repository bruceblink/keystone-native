package app.keystone.role;

/** 角色仍有成员时拒绝删除，避免删除角色后移除用户的授权关联。 */
public final class RoleHasAssignedUsersException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public RoleHasAssignedUsersException() {
        super("role has assigned users");
    }
}
