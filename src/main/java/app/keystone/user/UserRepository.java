package app.keystone.user;

import app.keystone.auth.DataScopeService;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
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
    @Inject AuthorizationService authorization;
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

    private User findPublic(String id, DataScopeService.Scope scope, String subjectId) {
        try {
            return ormUsers.findUser(id, scope, subjectId);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not find user", e);
        }
    }

    /** 用户管理命令的显式授权入口；仓储只接收已经解析的范围。 */
    public User findPublic(AuthorizationContext context, String id) {
        authorization.require(context, "user:read", "user");
        return findPublic(id, context.scope(), context.subjectId());
    }

    private Page list(int page, int size, String username, String displayName, String deptId, Boolean enabled,
                     DataScopeService.Scope scope, String subjectId) {
        try {
            return ormUsers.listUsers(page, size, username, displayName, deptId, enabled, scope, subjectId);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not list users", e);
        }
    }

    public Page list(AuthorizationContext context, int page, int size, String username, String displayName,
                     String deptId, Boolean enabled) {
        authorization.require(context, "user:read", "user");
        return list(page, size, username, displayName, deptId, enabled, context.scope(), context.subjectId());
    }

    /** 用户导出复用同一范围查询，并读取完整结果集。 */
    public List<User> export(AuthorizationContext context, String username, String displayName,
                             String deptId, Boolean enabled) {
        authorization.require(context, "user:export", "user");
        try {
            return ormUsers.exportUsers(username, displayName, deptId, enabled, context.scope(), context.subjectId());
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not export users", e);
        }
    }

    private User create(String username, String password, String displayName, String deptId, List<String> roleCodes) {
        return create(username, password, displayName, deptId, null, null, null, null, null, null, roleCodes);
    }

    public User create(AuthorizationContext context, String username, String password, String displayName,
                       String deptId, String postId, String email, String phoneNumber, Integer sex,
                       String avatar, String remark, List<String> roleCodes) {
        authorization.require(context, "user:create", "user");
        if (!context.scope().allowsDepartment(deptId)) throw new app.keystone.auth.AuthorizationDeniedException(
                "data_scope_denied", 403, "data scope does not allow this department");
        return create(username, password, displayName, deptId, postId, email, phoneNumber, sex, avatar, remark, roleCodes);
    }

    private User create(String username, String password, String displayName, String deptId, String postId, String email, String phoneNumber, Integer sex, String avatar, String remark, List<String> roleCodes) {
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

    private User update(String id, String password, String displayName, String deptId, Boolean enabled, List<String> roleCodes) {
        return updateExtended(id, password, displayName, deptId != null, deptId, null, null, null, null, null, null, enabled, roleCodes);
    }

    public User update(AuthorizationContext context, String id, String password, String displayName,
                       String deptId, Boolean enabled, List<String> roleCodes) {
        authorization.require(context, "user:update", "user");
        findPublic(context, id);
        if (deptId != null && !context.scope().allowsDepartment(deptId)) throw new app.keystone.auth.AuthorizationDeniedException(
                "data_scope_denied", 403, "data scope does not allow this department");
        return update(id, password, displayName, deptId, enabled, roleCodes);
    }

    public User updatePassword(AuthorizationContext context, String id, String password) {
        authorization.require(context, "user:reset-password", "user");
        findPublic(context, id);
        return update(id, password, null, null, null, null);
    }

    /** 初次密码修改由认证流程调用，要求内部系统能力，不接受外部用户上下文。 */
    public User updateInitialPassword(AuthorizationContext context, String id, String password) {
        if (context == null || !context.isSystem()) throw new app.keystone.auth.AuthorizationDeniedException(
                "permission_denied", 403, "internal authentication context required");
        return update(id, password, null, null, null, null);
    }

    public User updateStatus(AuthorizationContext context, String id, Boolean enabled) {
        authorization.require(context, "user:update", "user");
        findPublic(context, id);
        return update(id, null, null, null, enabled, null);
    }

    private User updateExtended(String id, String password, String displayName, boolean updateDept, String deptId, String postId, String email, String phoneNumber, Integer sex, String avatar, String remark, Boolean enabled, List<String> roleCodes) {
        try {
            return ormUsers.updateUser(id, password, displayName, updateDept, deptId, postId,
                    email, phoneNumber, sex, avatar, remark, enabled, roleCodes, passwordPolicy);
        } catch (IllegalArgumentException | java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update user", e);
        }
    }

    public User updateExtended(AuthorizationContext context, String id, String password, String displayName,
                               boolean updateDept, String deptId, String postId, String email, String phoneNumber,
                               Integer sex, String avatar, String remark, Boolean enabled, List<String> roleCodes) {
        authorization.require(context, "user:update", "user");
        findPublic(context, id);
        if (updateDept && !context.scope().allowsDepartment(deptId)) throw new app.keystone.auth.AuthorizationDeniedException(
                "data_scope_denied", 403, "data scope does not allow this department");
        return updateExtended(id, password, displayName, updateDept, deptId, postId, email, phoneNumber, sex, avatar, remark, enabled, roleCodes);
    }

    public void markLogin(String id, String ip) {
        try {
            ormUsers.markLogin(id, ip);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update login metadata", e);
        }
    }

    private void delete(String id, DataScopeService.Scope scope, String subjectId) {
        try {
            ormUsers.deleteUser(id, scope, subjectId);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete user", e);
        }
    }

    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "user:delete", "user");
        delete(id, context.scope(), context.subjectId());
    }

    private int deleteAll(List<String> ids, DataScopeService.Scope scope, String subjectId) {
        try {
            return ormUsers.deleteUsers(ids, scope, subjectId);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete users", e);
        }
    }

    public int deleteAll(AuthorizationContext context, List<String> ids) {
        authorization.require(context, "user:delete", "user");
        return deleteAll(ids, context.scope(), context.subjectId());
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
