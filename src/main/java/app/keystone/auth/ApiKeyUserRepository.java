package app.keystone.auth;

import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import jakarta.persistence.LockModeType;

import java.util.Set;
import java.util.Optional;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import app.keystone.user.User;
import app.keystone.user.UserRepository;
import app.keystone.user.PasswordPolicy;

/** 通过 ORM 读取 API Key 认证主体和签发权限。 */
@ApplicationScoped
public class ApiKeyUserRepository implements PanacheRepositoryBase<ApiKeyUserEntity, Long> {
    @jakarta.inject.Inject ApiKeyRoleRepository roles;

    ApiKeyUserEntity findEnabled(long userId) {
        ApiKeyUserEntity user = find("id = ?1 and enabled = true", userId).firstResult();
        return user != null && user.enabled() ? user : null;
    }

    @Transactional
    public Optional<UserRepository.AuthUser> findAuthUser(long userId) {
        ApiKeyUserEntity user = findEnabled(userId);
        return user == null ? Optional.empty() : Optional.of(user.toAuthUser());
    }

    @Transactional
    public Optional<UserRepository.AuthUser> findAuthUserByUsername(String username) {
        if (username == null || username.isBlank()) return Optional.empty();
        ApiKeyUserEntity user = find("username = ?1 and enabled = true", username).firstResult();
        return user == null ? Optional.empty() : Optional.of(user.toAuthUser());
    }

    /** 在一个 ORM 事务中创建用户并绑定启用角色。 */
    @Transactional
    public User createUser(String username, String passwordHash, String displayName, Long deptId, Long postId,
                           String email, String phoneNumber, Integer sex, String avatar, String remark,
                           List<String> roleCodes) {
        var resolvedRoles = resolveRoles(roleCodes);
        var user = new ApiKeyUserEntity(username, passwordHash, displayName, deptId, postId,
                email, phoneNumber, sex, avatar, remark);
        persistAndFlush(user);
        user.replaceRoles(resolvedRoles);
        return user.toUser();
    }

    /** 在一条用户写锁事务中完成资料、密码和角色更新。 */
    @Transactional
    public User updateUser(long userId, String password, String displayName, boolean updateDept, Long deptId,
                           Long postId, String email, String phoneNumber, Integer sex, String avatar,
                           String remark, Boolean enabled, List<String> roleCodes, PasswordPolicy passwordPolicy) {
        ApiKeyUserEntity user = find("id = ?1", userId)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
        if (user == null) throw new java.util.NoSuchElementException("user not found");
        Set<ApiKeyRoleEntity> replacement = roleCodes == null ? null : resolveRoles(roleCodes);
        if (password != null && !password.isBlank()) {
            passwordPolicy.validate(user.username(), password);
            user.changePassword(BcryptUtil.bcryptHash(password), Instant.now());
        }
        user.updateProfile(displayName, updateDept, deptId, postId, email, phoneNumber, sex, avatar, remark, enabled);
        if (replacement != null) {
            user.replaceRoles(replacement);
            user.bumpPermissionVersion();
        }
        return user.toUser();
    }

    /** 在事务内按筛选条件和数据范围分页读取用户。 */
    @Transactional
    public UserRepository.Page listUsers(int page, int size, String username, String displayName,
                                         Long deptId, Boolean enabled, DataScopeService.Scope scope,
                                         long subjectId) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        var query = userQuery(username, displayName, deptId, enabled, scope, subjectId);
        long total = query.count();
        var users = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(ApiKeyUserEntity::toUser).toList();
        return new UserRepository.Page(users, safePage, safeSize, total);
    }

    /** 在事务内按主体数据范围读取单个用户。 */
    @Transactional
    public User findUser(long userId, DataScopeService.Scope scope, long subjectId) {
        var parameters = new java.util.ArrayList<Object>();
        parameters.add(userId);
        var scoped = new StringBuilder("id = ?1");
        appendScope(scoped, parameters, scope, subjectId);
        ApiKeyUserEntity user = find(scoped.toString(), parameters.toArray()).firstResult();
        if (user == null) throw new java.util.NoSuchElementException("user not found");
        return user.toUser();
    }

    /** 按数据范围锁定并删除单个用户，管理员账号始终受保护。 */
    @Transactional
    public void deleteUser(long userId, DataScopeService.Scope scope, long subjectId) {
        ApiKeyUserEntity user = findScopedForUpdate(userId, scope, subjectId);
        if (user == null) throw new java.util.NoSuchElementException("user not found or protected");
        delete(user);
    }

    /** 按数据范围批量删除用户，跳过不存在、管理员和范围外记录。 */
    @Transactional
    public int deleteUsers(List<Long> userIds, DataScopeService.Scope scope, long subjectId) {
        if (userIds == null || userIds.isEmpty()) return 0;
        int deleted = 0;
        for (Long userId : userIds) {
            if (userId == null) continue;
            ApiKeyUserEntity user = findScopedForUpdate(userId, scope, subjectId);
            if (user != null) {
                delete(user);
                deleted++;
            }
        }
        return deleted;
    }

    /**
     * 在同一事务中锁定用户、校验密码并更新失败锁定状态。
     * 用户行写锁保证并发失败请求不会覆盖失败计数。
     */
    @Transactional
    public Optional<UserRepository.AuthUser> authenticate(String username, String password,
                                                          long accountLockBaseSeconds,
                                                          long accountLockMaxSeconds) {
        UserRepository.validateLockConfiguration(accountLockBaseSeconds, accountLockMaxSeconds);
        if (username == null || username.isBlank()) return Optional.empty();
        ApiKeyUserEntity user = find("username = ?1 and enabled = true", username)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
        if (user == null) return Optional.empty();

        java.time.Instant now = java.time.Instant.now();
        if (user.lockedUntil() != null && user.lockedUntil().isAfter(now)) return Optional.empty();
        if (password == null || !BcryptUtil.matches(password, user.passwordHash())) {
            int attempts = user.failedLoginCount() + 1;
            java.time.Instant lockedUntil = attempts >= 5
                    ? now.plusSeconds(UserRepository.calculateLockDelaySeconds(accountLockBaseSeconds, accountLockMaxSeconds, attempts))
                    : null;
            user.recordFailedLogin(attempts, lockedUntil);
            return Optional.empty();
        }
        user.clearFailedLogins();
        return Optional.of(user.toAuthUser());
    }

    /** 使用用户行写锁更新密码，确保失败锁定和凭据版本在同一事务内变化。 */
    @Transactional
    public User updatePassword(long userId, String password, PasswordPolicy passwordPolicy) {
        ApiKeyUserEntity user = find("id = ?1", userId)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
        if (user == null) throw new java.util.NoSuchElementException("user not found");
        passwordPolicy.validate(user.username(), password);
        user.changePassword(BcryptUtil.bcryptHash(password), Instant.now());
        return user.toUser();
    }

    @Transactional
    public Set<String> permissions(long userId) {
        ApiKeyUserEntity user = findEnabled(userId);
        return user == null ? Set.of() : user.permissions();
    }

    @Transactional
    boolean hasPermission(long userId, String permission) {
        return permissions(userId).contains(permission);
    }

    @Transactional
    boolean hasPermissionByUsername(String username, String permission) {
        if (username == null || username.isBlank()) return false;
        ApiKeyUserEntity user = find("username = ?1 and enabled = true", username).firstResult();
        return user != null && user.permissions().contains(permission);
    }

    @Transactional
    public long permissionVersion(long userId) {
        ApiKeyUserEntity user = findEnabled(userId);
        return user == null ? -1 : user.permissionVersion();
    }

    @Transactional
    public void markLogin(long userId, String ipAddress) {
        ApiKeyUserEntity user = findById(userId);
        if (user != null) user.markLogin(ipAddress, Instant.now());
    }

    ApiKeyUserEntity findEnabledEntity(long userId) {
        return findEnabled(userId);
    }

    ApiKeyUserEntity findForUpdate(long userId) {
        ApiKeyUserEntity user = find("id = ?1 and enabled = true", userId)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
        return user != null && user.enabled() ? user : null;
    }

    /** 在 MFA 和其他安全状态事务中锁定用户行，包括已禁用用户。 */
    ApiKeyUserEntity findAnyForUpdate(long userId) {
        return find("id = ?1", userId).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
    }

    List<ApiKeyUserEntity> findUsersByIdsForUpdate(List<Long> userIds) {
        if (userIds == null || userIds.isEmpty()) return List.of();
        return find("id in ?1", userIds).withLock(LockModeType.PESSIMISTIC_WRITE).list();
    }

    List<ApiKeyUserEntity> findUsersWithRole(long roleId) {
        return find("select distinct u from ApiKeyUserEntity u join u.roles r where r.id = ?1 order by u.id", roleId).list();
    }

    List<Long> findUserIdsByRole(long roleId, boolean allocated) {
        if (allocated) {
            return find("select distinct u from ApiKeyUserEntity u join u.roles r where r.id = ?1 order by u.id", roleId)
                    .list().stream().map(ApiKeyUserEntity::id).toList();
        }
        return find("select u from ApiKeyUserEntity u where not exists (select r.id from u.roles r where r.id = ?1) order by u.id", roleId)
                .list().stream().map(ApiKeyUserEntity::id).toList();
    }

    java.util.Set<String> permissions(ApiKeyUserEntity user) {
        return user == null ? java.util.Set.of() : user.permissions();
    }

    private Set<ApiKeyRoleEntity> resolveRoles(List<String> roleCodes) {
        var normalized = new LinkedHashSet<String>();
        for (String code : roleCodes == null ? List.<String>of("USER") : roleCodes) {
            if (code != null && !code.isBlank()) normalized.add(code.trim());
        }
        if (normalized.isEmpty()) normalized.add("USER");
        var found = roles.findEnabledByCodes(List.copyOf(normalized));
        if (found.size() != normalized.size()) {
            var foundCodes = found.stream().map(ApiKeyRoleEntity::code).collect(java.util.stream.Collectors.toSet());
            var unknown = normalized.stream().filter(code -> !foundCodes.contains(code)).findFirst().orElse("unknown");
            throw new IllegalArgumentException("unknown role: " + unknown);
        }
        return new LinkedHashSet<>(found);
    }

    private ApiKeyUserEntity findScopedForUpdate(long userId, DataScopeService.Scope scope, long subjectId) {
        var query = new StringBuilder("id = ?1 and username <> 'admin'");
        var parameters = new java.util.ArrayList<Object>();
        parameters.add(userId);
        appendScope(query, parameters, scope, subjectId);
        return find(query.toString(), parameters.toArray()).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
    }

    private PanacheQuery<ApiKeyUserEntity> userQuery(String username, String displayName, Long deptId,
                                                       Boolean enabled, DataScopeService.Scope scope,
                                                       long subjectId) {
        var query = new StringBuilder("1 = 1");
        var parameters = new java.util.ArrayList<Object>();
        if (username != null && !username.isBlank()) {
            parameters.add("%" + username.trim() + "%");
            query.append(" and username like ?").append(parameters.size());
        }
        if (displayName != null && !displayName.isBlank()) {
            parameters.add("%" + displayName.trim() + "%");
            query.append(" and displayName like ?").append(parameters.size());
        }
        if (deptId != null) {
            parameters.add(deptId);
            query.append(" and deptId = ?").append(parameters.size());
        }
        if (enabled != null) {
            parameters.add(enabled);
            query.append(" and enabled = ?").append(parameters.size());
        }
        appendScope(query, parameters, scope, subjectId);
        query.append(" order by id");
        return find(query.toString(), parameters.toArray());
    }

    private static void appendScope(StringBuilder query, List<Object> parameters,
                                    DataScopeService.Scope scope, long subjectId) {
        if (scope.all()) return;
        var clauses = new java.util.ArrayList<String>();
        if (scope.self()) {
            parameters.add(subjectId);
            clauses.add("id = ?" + parameters.size());
        }
        if (!scope.departments().isEmpty()) {
            var placeholders = new java.util.ArrayList<String>();
            for (Long department : scope.departments()) {
                parameters.add(department);
                placeholders.add("?" + parameters.size());
            }
            clauses.add("deptId in (" + String.join(", ", placeholders) + ")");
        }
        query.append(" and ").append(clauses.isEmpty() ? "1 = 0" : "(" + String.join(" or ", clauses) + ")");
    }
}
