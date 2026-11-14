package app.keystone.role;

import app.keystone.auth.RoleAdminOrmRepository;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

/** 角色管理入口；具体持久化由 ORM 仓储负责。 */
@ApplicationScoped
public class RoleRepository {
    @Inject RoleAdminOrmRepository ormRoles;
    @Inject AuthorizationService authorization;

    public List<Role> list(AuthorizationContext context) {
        authorization.require(context, "role:read", "role");
        return ormRoles.listRoles();
    }

    /** 角色导出复用全量查询和资源范围检查。 */
    public List<Role> export(AuthorizationContext context) {
        authorization.require(context, "role:export", "role");
        return ormRoles.listRoles();
    }

    public Role create(AuthorizationContext context, String code, String name) {
        authorization.require(context, "role:create", "role");
        require(code, "code");
        require(name, "name");
        try {
            return ormRoles.createRole(code.trim(), name.trim());
        } catch (RuntimeException e) {
            if (isUniqueConstraint(e)) throw new IllegalArgumentException("role code already exists", e);
            throw new IllegalStateException("Could not create role", e);
        }
    }

    public Role update(AuthorizationContext context, String code, String name, Boolean enabled) {
        authorization.require(context, "role:update", "role");
        return updateExtended(context, code, name, enabled, null, null);
    }

    /** 通过公开 UUID 主键更新角色；角色 code 仅作为业务标识保存。 */
    public Role updateById(AuthorizationContext context, String id, String name, Boolean enabled) {
        authorization.require(context, "role:update", "role");
        requireId(id);
        return ormRoles.updateRoleById(id, name, enabled, null, null);
    }

    public Role updateExtended(AuthorizationContext context, String code, String name, Boolean enabled, String dataScope, String deptScope) {
        authorization.require(context, "role:update", "role");
        try {
            return ormRoles.updateRole(code, name, enabled, dataScope, deptScope);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update role", e);
        }
    }

    public void delete(AuthorizationContext context, String code) {
        authorization.require(context, "role:delete", "role");
        try {
            ormRoles.deleteRole(code);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete role", e);
        }
    }

    /** 通过公开 UUID 主键删除角色。 */
    public void deleteById(AuthorizationContext context, String id) {
        authorization.require(context, "role:delete", "role");
        requireId(id);
        ormRoles.deleteRoleById(id);
    }

    public Role findById(AuthorizationContext context, String id) {
        authorization.require(context, "role:read", "role");
        return ormRoles.findRoleById(id);
    }

    public Role findByCode(AuthorizationContext context, String code) {
        authorization.require(context, "role:read", "role");
        return ormRoles.findByCode(code);
    }

    public void assignPermissions(AuthorizationContext context, String code, List<String> permissions) {
        authorization.require(context, "role:manage", "role");
        try {
            ormRoles.assignPermissions(code, permissions);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not assign role permissions", e);
        }
    }

    /** 通过公开 UUID 主键替换角色权限。 */
    public void assignPermissionsById(AuthorizationContext context, String id, List<String> permissions) {
        authorization.require(context, "role:manage", "role");
        requireId(id);
        ormRoles.assignPermissionsById(id, permissions);
    }

    public void assignUsers(AuthorizationContext context, String code, List<String> userIds) {
        authorization.require(context, "role:manage", "role");
        try {
            ormRoles.assignUsers(code, userIds);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not grant role users", e);
        }
    }

    public void revokeUsers(AuthorizationContext context, String code, List<String> userIds) {
        authorization.require(context, "role:manage", "role");
        try {
            ormRoles.revokeUsers(code, userIds);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not revoke role users", e);
        }
    }

    public List<String> userIds(AuthorizationContext context, String code, boolean allocated) {
        authorization.require(context, "role:read", "role");
        return ormRoles.userIds(code, allocated);
    }

    /** 通过 UUID 主键执行角色用户分配，并使用独立的 role:assign 权限。 */
    public void assignUsersById(AuthorizationContext context, String id, List<String> userIds) {
        authorization.require(context, "role:assign", "role");
        requireId(id);
        try {
            ormRoles.assignUsersById(id, userIds);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not grant role users", e);
        }
    }

    /** 通过 UUID 主键撤销角色用户分配，并在同一事务中更新权限版本。 */
    public void revokeUsersById(AuthorizationContext context, String id, List<String> userIds) {
        authorization.require(context, "role:assign", "role");
        requireId(id);
        try {
            ormRoles.revokeUsersById(id, userIds);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not revoke role users", e);
        }
    }

    /** 按 UUID 主键读取角色成员或未分配用户的 ID 列表。 */
    public List<String> userIdsById(AuthorizationContext context, String id, boolean allocated) {
        authorization.require(context, "role:read", "role");
        requireId(id);
        return ormRoles.userIdsById(id, allocated);
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static void requireId(String value) {
        try {
            app.keystone.identity.UuidValues.requireCanonical(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("id must be a UUID", e);
        }
    }

    private static boolean isUniqueConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("unique")) return true;
        }
        return false;
    }
}
