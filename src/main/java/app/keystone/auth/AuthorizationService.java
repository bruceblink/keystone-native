package app.keystone.auth;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Set;

@ApplicationScoped
public class AuthorizationService {
    @Inject ApiKeyUserRepository users;
    @Inject DataScopeService dataScopes;

    /** 将认证入口的主体解析为可传递给业务命令的不可变授权上下文。 */
    public AuthorizationContext context(SecurityIdentity identity) {
        if (identity == null || identity.isAnonymous()) {
            throw denied("invalid_credential", 401, "authentication is required");
        }
        String username = identity.getPrincipal().getName();
        String subjectId = subjectId(identity, username);
        Set<String> permissions = users.permissions(subjectId);
        DataScopeService.Scope scope = dataScopes.forUser(subjectId);
        return AuthorizationContext.user(
                subjectId,
                username,
                String.valueOf((Object) identity.getAttribute("credentialType")),
                permissions,
                scope);
    }

    /** 在业务命令内部执行权限和资源范围检查。 */
    public void require(AuthorizationContext context, String permission, String resource) {
        if (context == null) throw denied("invalid_credential", 401, "authentication is required");
        if (!PermissionCatalog.contains(permission) || !context.hasPermission(permission)) {
            throw denied("permission_denied", 403, "permission denied");
        }
        DataScopePolicy.ResourceRule rule = DataScopePolicy.rule(resource);
        if (rule == null || !DataScopePolicy.allows(rule, context.allScope(), context.selfScope())) {
            throw denied("data_scope_denied", 403, "data scope does not allow this resource");
        }
    }

    public boolean allowed(SecurityIdentity identity, String permission) {
        if (identity == null || identity.isAnonymous() || !PermissionCatalog.contains(permission)) return false;
        Object credentialType = identity.getAttribute("credentialType");
        if ("API_KEY".equals(credentialType)) {
            Object scopes = identity.getAttribute("scopes");
            Object userId = identity.getAttribute("userId");
            if (!(userId instanceof String id) || !(scopes instanceof List<?> values) || values.stream().noneMatch(permission::equals)) return false;
            // API Key 权限必须同时满足签发范围和主体当前权限，角色变更会立即收紧结果。
            return users.hasPermission(id, permission);
        }
        return users.hasPermissionByUsername(identity.getPrincipal().getName(), permission);
    }

    private String subjectId(SecurityIdentity identity, String username) {
        Object value = identity.getAttribute("userId");
        if (value instanceof String id && !id.isBlank()) return app.keystone.identity.UuidValues.requireCanonical(id);
        return users.findAuthUserByUsername(username)
                .orElseThrow(() -> denied("invalid_credential", 401, "subject is unavailable"))
                .id();
    }

    private static AuthorizationDeniedException denied(String code, int status, String message) {
        return new AuthorizationDeniedException(code, status, message);
    }
}
