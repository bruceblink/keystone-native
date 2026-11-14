package app.keystone.auth;

import app.keystone.role.Role;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** 使用 ORM 完成角色、权限和角色成员的事务更新。 */
@ApplicationScoped
public class RoleAdminOrmRepository implements PanacheRepositoryBase<ApiKeyRoleEntity, java.util.UUID> {
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
    public Role updateRoleById(String id, String name, Boolean enabled, String dataScope, String deptScope) {
        ApiKeyRoleEntity role = findRoleEntityById(id);
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
    public void deleteRoleById(String id) {
        ApiKeyRoleEntity role = findRoleEntityById(id);
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        bumpPermissionVersion(role);
        delete(role);
    }

    /** 在同一事务内锁定并删除全部角色，任何目标缺失时整体回滚。 */
    @Transactional
    public int deleteRolesByIds(List<String> ids) {
        List<String> normalized = (ids == null ? List.<String>of() : ids).stream()
                .map(app.keystone.identity.UuidValues::requireCanonical)
                .distinct()
                .toList();
        if (normalized.isEmpty()) throw new IllegalArgumentException("ids is required");
        List<UUID> values = normalized.stream().map(app.keystone.identity.UuidValues::parse).toList();
        List<ApiKeyRoleEntity> roles = find("id in ?1", values).withLock(LockModeType.PESSIMISTIC_WRITE).list();
        if (roles.size() != values.size()) throw new java.util.NoSuchElementException("role not found");
        roles.forEach(this::deleteRoleEntity);
        return roles.size();
    }

    private void deleteRoleEntity(ApiKeyRoleEntity role) {
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
    public void assignPermissionsById(String id, List<String> permissionCodes) {
        ApiKeyRoleEntity role = findRoleEntityById(id);
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        Set<ApiKeyPermissionEntity> resolved = resolvePermissions(permissionCodes);
        role.replacePermissions(resolved);
        bumpPermissionVersion(role);
    }

    @Transactional
    public void assignUsers(String code, List<String> userIds) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        assignUsers(role, userIds);
    }

    @Transactional
    public void revokeUsers(String code, List<String> userIds) {
        ApiKeyRoleEntity role = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        revokeUsers(role, userIds);
    }

    /** 使用 UUID 主键更新角色成员，角色行锁与用户行锁处于同一事务。 */
    @Transactional
    public void assignUsersById(String id, List<String> userIds) {
        ApiKeyRoleEntity role = findRoleEntityByIdForUpdate(id);
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        assignUsersStrict(role, userIds);
    }

    /** 使用 UUID 主键撤销角色成员，角色行锁与用户行锁处于同一事务。 */
    @Transactional
    public void revokeUsersById(String id, List<String> userIds) {
        ApiKeyRoleEntity role = findRoleEntityByIdForUpdate(id);
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        revokeUsersStrict(role, userIds);
    }

    @Transactional
    public Role findRoleById(String id) {
        ApiKeyRoleEntity role = findRoleEntityById(id);
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
    public List<String> userIds(String code, boolean allocated) {
        ApiKeyRoleEntity role = find("code", code).firstResult();
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        return users.findUserIdsByRole(role.uuid(), allocated);
    }

    @Transactional
    public List<String> userIdsById(String id, boolean allocated) {
        ApiKeyRoleEntity role = findRoleEntityById(id);
        if (role == null) throw new java.util.NoSuchElementException("role not found");
        return users.findUserIdsByRole(role.uuid(), allocated);
    }

    private void assignUsers(ApiKeyRoleEntity role, List<String> userIds) {
        for (ApiKeyUserEntity user : users.findUsersByIdsForUpdate(userIds)) {
            if (user.addRole(role)) user.bumpPermissionVersion();
        }
    }

    private void revokeUsers(ApiKeyRoleEntity role, List<String> userIds) {
        for (ApiKeyUserEntity user : users.findUsersByIdsForUpdate(userIds)) {
            if (user.removeRole(role)) user.bumpPermissionVersion();
        }
    }

    /** 新 HTTP 批量入口要求所有目标用户存在，避免静默跳过造成部分成功。 */
    private void assignUsersStrict(ApiKeyRoleEntity role, List<String> userIds) {
        for (ApiKeyUserEntity user : assignmentUsers(userIds)) {
            if (user.addRole(role)) user.bumpPermissionVersion();
        }
    }

    /** 新 HTTP 批量入口在任何目标缺失时整体失败并回滚。 */
    private void revokeUsersStrict(ApiKeyRoleEntity role, List<String> userIds) {
        for (ApiKeyUserEntity user : assignmentUsers(userIds)) {
            if (user.removeRole(role)) user.bumpPermissionVersion();
        }
    }

    private List<ApiKeyUserEntity> assignmentUsers(List<String> userIds) {
        List<String> normalized = (userIds == null ? List.<String>of() : userIds).stream()
                .map(app.keystone.identity.UuidValues::requireCanonical)
                .distinct()
                .toList();
        List<ApiKeyUserEntity> found = users.findUsersByIdsForUpdate(normalized);
        if (found.size() != normalized.size()) throw new java.util.NoSuchElementException("user not found");
        return found;
    }

    private ApiKeyRoleEntity findRoleEntityById(String id) {
        return find("id", app.keystone.identity.UuidValues.parse(id)).firstResult();
    }

    private ApiKeyRoleEntity findRoleEntityByIdForUpdate(String id) {
        return find("id", app.keystone.identity.UuidValues.parse(id))
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
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
        for (ApiKeyUserEntity user : users.findUsersWithRole(role.uuid())) user.bumpPermissionVersion();
    }
}
