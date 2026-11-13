package app.keystone.auth;

import java.util.Set;

/**
 * 统一权限目录；接口、服务和 API Key 只能使用这里声明的两段权限。
 * 菜单和角色名称不参与权限判定，数据库目录由同一组标识初始化。
 */
public final class PermissionCatalog {
    private static final Set<String> VALUES = Set.of(
            "api-key:create", "api-key:read", "api-key:revoke", "api-key:rotate",
            "audit:delete", "audit:export", "audit:read", "cache:refresh",
            "config:create", "config:read", "config:refresh", "config:update",
            "department:create", "department:delete", "department:read", "department:update",
            "dictionary:create", "dictionary:delete", "dictionary:read", "dictionary:refresh", "dictionary:update",
            "file:read", "file:write",
            "job:create", "job:delete", "job:read", "job:run", "job:update", "job:update-status",
            "login-log:delete", "login-log:export", "login-log:read",
            "menu:create", "menu:delete", "menu:manage", "menu:read", "menu:update",
            "mfa:manage", "notice:create", "notice:delete", "notice:read", "notice:update",
            "online-session:read", "online-session:revoke",
            "operation-log:delete", "operation-log:export", "operation-log:read",
            "permission:manage", "permission:read",
            "post:create", "post:delete", "post:export", "post:read", "post:update",
            "role:assign", "role:create", "role:delete", "role:export", "role:manage", "role:read", "role:update",
            "server:read", "session:read", "session:revoke",
            "user:create", "user:delete", "user:export", "user:import", "user:read", "user:reset-password", "user:update");

    private PermissionCatalog() {
    }

    public static boolean contains(String permission) {
        return permission != null && VALUES.contains(permission);
    }

    public static Set<String> values() {
        return VALUES;
    }
}
