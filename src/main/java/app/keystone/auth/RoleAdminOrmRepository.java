package app.keystone.auth;

import app.keystone.role.Role;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** 使用 ORM 完成角色、权限和角色成员的事务更新。 */
@ApplicationScoped
public class RoleAdminOrmRepository implements PanacheRepositoryBase<ApiKeyRoleEntity, Long> {
    @jakarta.inject.Inject ApiKeyPermissionRepository permissions;
    @jakarta.inject.Inject ApiKeyUserRepository users;

    @Transactional
    public List<Role> listRoles() {
        return find("order by code").list().stream().map(ApiKeyRoleEntity::toRole).toList();
    }

    @Transactional
    public Role createRole(String code, String name) {
        var role = new ApiKeyRoleEntity(code.trim(), name.trim());
        persistAndFlush(role);
        return role.toRole();
    }

    @Transactional
    public Role updateRole(String code, String name, Boolean enabled, String dataScope, String deptScope) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        boolean changed = name != null && !name.isBlank() || enabled != null
                || dataScope != null && !dataScope.isBlank() || deptScope != null;
        role.update(name, enabled, dataScope, deptScope);
        if (changed) bumpPermissionVersion(role);
        return role.toRole();
    }

    @Transactional
    public void deleteRole(String code) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        bumpPermissionVersion(role);
        delete(role);
    }

    @Transactional
    public void assignPermissions(String code, List<String> permissionCodes) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        Set<ApiKeyPermissionEntity> resolved = resolvePermissions(permissionCodes);
        role.replacePermissions(resolved);
        bumpPermissionVersion(role);
    }

    @Transactional
    public void assignUsers(String code, List<Long> userIds) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        for (ApiKeyUserEntity user : users.findUsersByIdsForUpdate(userIds)) {
            if (user.addRole(role)) user.bumpPermissionVersion();
        }
    }

    @Transactional
    public void revokeUsers(String code, List<Long> userIds) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        for (ApiKeyUserEntity user : users.findUsersByIdsForUpdate(userIds)) {
            if (user.removeRole(role)) user.bumpPermissionVersion();
        }
    }

    @Transactional
    public Role findById(long id) {
        ApiKeyRoleEntity role = findByIdOptional(id);
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        return role.toRole();
    }

    @Transactional
    public Role findByCode(String code) {
        ApiKeyRoleEntity role = find("code", code).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        return role.toRole();
    }

    @Transactional
    public List<Long> userIds(String code, boolean allocated) {
        ApiKeyRoleEntity role = find("code", code).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        return users.findUserIdsByRole(role.id(), allocated);
    }

    private ApiKeyRoleEntity findByIdOptional(long id) {
        return find("id", id).firstResult();
    }

    private Set<ApiKeyPermissionEntity> resolvePermissions(List<String> permissionCodes) {
        var normalized = new LinkedHashSet<String>();
        for (String code : permissionCodes == null ? List.<String>of() : permissionCodes) {
            if (code != null && !code.isBlank()) {
                String value = code.trim();
                if (!PermissionCatalog.contains(value)) throw new IllegalArgumentException("unknown permission: " + value);
                normalized.add(value);
            }
        }
        var found = permissions.findByCodes(List.copyOf(normalized));
        if (found.size() != normalized.size()) {
            var foundCodes = found.stream().map(ApiKeyPermissionEntity::code).collect(java.util.stream.Collectors.toSet());
            var unknown = normalized.stream().filter(code -> !foundCodes.contains(code)).findFirst().orElse("unknown");
            throw new IllegalArgumentException("unknown permission: " + unknown);
        }
        return new LinkedHashSet<>(found);
    }

    private void bumpPermissionVersion(ApiKeyRoleEntity role) {
        for (ApiKeyUserEntity user : users.findUsersWithRole(role.id())) user.bumpPermissionVersion();
    }
}
