package app.keystone.user;

import app.keystone.auth.DataScopeService;
import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserRepository {
    @Inject app.keystone.auth.ApiKeyUserRepository ormUsers;
    @Inject PasswordPolicy passwordPolicy;
    @ConfigProperty(name = "keystone.security.login.account-lock-base-seconds", defaultValue = "60")
    long accountLockBaseSeconds;
    @ConfigProperty(name = "keystone.security.login.account-lock-max-seconds", defaultValue = "900")
    long accountLockMaxSeconds;

    public Optional<AuthUser> authenticate(String username, String password) {
        try {
            return ormUsers.authenticate(username, password, accountLockBaseSeconds, accountLockMaxSeconds);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not authenticate user", e);
        }
    }

    public Optional<AuthUser> findAuthUser(String id) {
        try {
            return ormUsers.findAuthUser(id);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not find user", e);
        }
    }

    public Optional<AuthUser> findAuthUserByUsername(String username) {
        try {
            return ormUsers.findAuthUserByUsername(username);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not find user", e);
        }
    }

    public User findPublic(String id, DataScopeService.Scope scope, String subjectId) {
        try {
            return ormUsers.findUser(id, scope, subjectId);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not find user", e);
        }
    }

    public Page list(int page, int size, String username, String displayName, String deptId, Boolean enabled,
                     DataScopeService.Scope scope, String subjectId) {
        try {
            return ormUsers.listUsers(page, size, username, displayName, deptId, enabled, scope, subjectId);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not list users", e);
        }
    }

    public User create(String username, String password, String displayName, String deptId, List<String> roleCodes) {
        return create(username, password, displayName, deptId, null, null, null, null, null, null, roleCodes);
    }

    public User create(String username, String password, String displayName, String deptId, String postId, String email, String phoneNumber, Integer sex, String avatar, String remark, List<String> roleCodes) {
        if (username == null || username.isBlank() || password == null || password.isBlank() || displayName == null || displayName.isBlank()) throw new IllegalArgumentException("username, password and displayName are required");
        passwordPolicy.validate(username, password);
        try {
            return ormUsers.createUser(username.trim(), BcryptUtil.bcryptHash(password), displayName.trim(),
                    deptId, postId, email, phoneNumber, sex, avatar, remark, roleCodes);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isUniqueConstraint(e)) throw new IllegalArgumentException("username already exists", e);
            throw new IllegalStateException("Could not create user", e);
        }
    }

    public User update(String id, String password, String displayName, String deptId, Boolean enabled, List<String> roleCodes) {
        return updateExtended(id, password, displayName, deptId != null, deptId, null, null, null, null, null, null, enabled, roleCodes);
    }

    public User updateExtended(String id, String password, String displayName, boolean updateDept, String deptId, String postId, String email, String phoneNumber, Integer sex, String avatar, String remark, Boolean enabled, List<String> roleCodes) {
        try {
            return ormUsers.updateUser(id, password, displayName, updateDept, deptId, postId,
                    email, phoneNumber, sex, avatar, remark, enabled, roleCodes, passwordPolicy);
        } catch (IllegalArgumentException | java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update user", e);
        }
    }

    public void markLogin(String id, String ip) {
        try {
            ormUsers.markLogin(id, ip);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update login metadata", e);
        }
    }

    public void delete(String id, DataScopeService.Scope scope, String subjectId) {
        try {
            ormUsers.deleteUser(id, scope, subjectId);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete user", e);
        }
    }

    public int deleteAll(List<String> ids, DataScopeService.Scope scope, String subjectId) {
        try {
            return ormUsers.deleteUsers(ids, scope, subjectId);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete users", e);
        }
    }

    /** 计算第 N 次失败的锁定秒数；结果不会超过部署配置的上限。 */
    public static long calculateLockDelaySeconds(long baseSeconds, long maxSeconds, int attempts) {
        if (baseSeconds <= 0 || maxSeconds < baseSeconds || maxSeconds > 86_400 || attempts < 5) {
            throw new IllegalArgumentException("account lock backoff parameters are invalid");
        }
        long delay = baseSeconds;
        int exponent = Math.max(0, attempts - 5);
        for (int i = 0; i < exponent && delay < maxSeconds; i++) {
            delay = Math.min(maxSeconds, delay > maxSeconds / 2 ? maxSeconds : delay * 2);
        }
        return Math.min(delay, maxSeconds);
    }

    /** 校验账户锁定退避配置，避免运行中出现溢出或无限锁定。 */
    public static void validateLockConfiguration(long baseSeconds, long maxSeconds) {
        if (baseSeconds <= 0 || maxSeconds < baseSeconds || maxSeconds > 86_400) {
            throw new IllegalStateException("account lock backoff configuration is invalid");
        }
    }

    public List<String> permissions(String userId) {
        try {
            return ormUsers.permissions(userId).stream().sorted().toList();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not list user permissions", e);
        }
    }
    /** 读取当前权限版本，访问令牌校验使用该值判断角色变化。 */
    public long permissionVersion(String userId) {
        try {
            return ormUsers.permissionVersion(userId);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not read user permission version", e);
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

    public record AuthUser(String id, String username, String displayName, List<String> roles, boolean mustChangePassword,
                           String deptId, String postId, String email, String phoneNumber, Integer sex, String avatar,
                           String loginIp, java.time.Instant loginAt, String remark) {}
    public record Page(List<User> items, int page, int size, long total) {}
}
