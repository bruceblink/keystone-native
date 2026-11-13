package app.keystone.auth;

import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
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
}
