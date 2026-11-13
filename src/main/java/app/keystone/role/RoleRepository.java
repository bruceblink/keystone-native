package app.keystone.role;

import app.keystone.auth.RoleAdminOrmRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

/** 角色管理入口；具体持久化由 ORM 仓储负责。 */
@ApplicationScoped
public class RoleRepository {
    @Inject RoleAdminOrmRepository ormRoles;

    public List<Role> list() {
        return ormRoles.listRoles();
    }

    public Role create(String code, String name) {
        require(code, "code");
        require(name, "name");
        try {
            return ormRoles.createRole(code.trim(), name.trim());
        } catch (RuntimeException e) {
            if (isUniqueConstraint(e)) throw new IllegalArgumentException("role code already exists", e);
            throw new IllegalStateException("Could not create role", e);
        }
    }

    public Role update(String code, String name, Boolean enabled) {
        return updateExtended(code, name, enabled, null, null);
    }

    /** 通过公开 UUID 主键更新角色；角色 code 仅作为业务标识保存。 */
    public Role updateById(String id, String name, Boolean enabled) {
        requireId(id);
        return ormRoles.updateRoleById(id, name, enabled, null, null);
    }

    public Role updateExtended(String code, String name, Boolean enabled, String dataScope, String deptScope) {
        try {
            return ormRoles.updateRole(code, name, enabled, dataScope, deptScope);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update role", e);
        }
    }

    public void delete(String code) {
        try {
            ormRoles.deleteRole(code);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete role", e);
        }
    }

    /** 通过公开 UUID 主键删除角色。 */
    public void deleteById(String id) {
        requireId(id);
        ormRoles.deleteRoleById(id);
    }

    public Role findById(String id) {
        return ormRoles.findRoleById(id);
    }

    public Role findByCode(String code) {
        return ormRoles.findByCode(code);
    }

    public void assignPermissions(String code, List<String> permissions) {
        try {
            ormRoles.assignPermissions(code, permissions);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not assign role permissions", e);
        }
    }

    /** 通过公开 UUID 主键替换角色权限。 */
    public void assignPermissionsById(String id, List<String> permissions) {
        requireId(id);
        ormRoles.assignPermissionsById(id, permissions);
    }

    public void assignUsers(String code, List<String> userIds) {
        try {
            ormRoles.assignUsers(code, userIds);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not grant role users", e);
        }
    }

    public void revokeUsers(String code, List<String> userIds) {
        try {
            ormRoles.revokeUsers(code, userIds);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not revoke role users", e);
        }
    }

    public List<String> userIds(String code, boolean allocated) {
        return ormRoles.userIds(code, allocated);
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
