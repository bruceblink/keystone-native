package app.keystone.auth;

import app.keystone.ErrorCode;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Set;
import java.util.LinkedHashSet;
import org.eclipse.microprofile.jwt.JsonWebToken;

@ApplicationScoped
public class AuthorizationService {
    @Inject ApiKeyUserRepository users;
    @Inject DataScopeService dataScopes;

    /** 将认证入口的主体解析为可传递给业务命令的不可变授权上下文。 */
    public AuthorizationContext context(SecurityIdentity identity) {
        if (identity == null || identity.isAnonymous()) {
            throw denied(ErrorCode.AUTHENTICATION_REQUIRED, "authentication is required");
        }
        String username = identity.getPrincipal().getName();
        String subjectId = subjectId(identity, username);
        Set<String> permissions = users.permissions(subjectId);
        DataScopeService.Scope scope = dataScopes.forUser(subjectId);
        JsonWebToken jwt = identity.getPrincipal() instanceof JsonWebToken token ? token : null;
        String credentialType = value(identity.getAttribute("credentialType"), jwt, "amr");
        credentialType = credentialType == null ? "PASSWORD" : normalizeCredentialType(credentialType);
        String credentialId = value(identity.getAttribute("credentialId"), jwt, "jti");
        String clientId = value(identity.getAttribute("clientId"), jwt, "client_id");
        Set<String> approvedScopes = scopes(identity.getAttribute("approvedScopes"), identity.getAttribute("scopes"), jwt);
        if (approvedScopes.isEmpty()) approvedScopes = permissions;
        long permissionVersion = number(identity.getAttribute("permissionVersion"), jwt, "permission_version", users.permissionVersion(subjectId));
        String authenticationLevel = value(identity.getAttribute("authenticationLevel"), jwt, "aal");
        return AuthorizationContext.user(
                subjectId,
                "API_KEY".equals(credentialType) ? "SERVICE" : "USER",
                username,
                credentialType,
                credentialId,
                clientId == null ? "web" : clientId,
                permissions,
                approvedScopes,
                dataScope(scope),
                permissionVersion,
                authenticationLevel == null ? "AAL1" : authenticationLevel,
                scope);
    }

    /** 在业务命令内部执行权限和资源范围检查。 */
    public void require(AuthorizationContext context, String permission, String resource) {
        require(context, permission, resource, null);
    }

    /** 在资源保存所有者时，额外核验主体与目标记录的所有者关系。 */
    public void require(AuthorizationContext context, String permission, String resource, String ownerId) {
        if (context == null) throw denied(ErrorCode.AUTHENTICATION_REQUIRED, "authentication is required");
        if (!PermissionCatalog.contains(permission) || !context.hasPermission(permission)) {
            throw denied(ErrorCode.PERMISSION_DENIED, "permission denied");
        }
        DataScopePolicy.ResourceRule rule = DataScopePolicy.rule(resource);
        if (rule == null || !DataScopePolicy.allows(rule, context.allScope(), context.selfScope(), context.ownerScope())) {
            throw denied(ErrorCode.DATA_SCOPE_DENIED, "data scope does not allow this resource");
        }
        if (ownerId != null && !context.isSystem() && !context.allScope()
                && (!(context.selfScope() || context.ownerScope()) || !context.subjectId().equals(ownerId))) {
            throw denied(ErrorCode.DATA_SCOPE_DENIED, "data scope does not allow this resource");
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
                .orElseThrow(() -> denied(ErrorCode.AUTHENTICATION_REQUIRED, "subject is unavailable"))
                .id();
    }

    private static String dataScope(DataScopeService.Scope scope) {
        if (scope.all()) return "ALL";
        if (scope.owner()) return "OWNER";
        if (scope.self()) return "SELF";
        return scope.departments().isEmpty() ? "NONE" : "CUSTOM";
    }

    private static Set<String> scopes(Object approved, Object scopes, JsonWebToken jwt) {
        Object source = approved != null ? approved : scopes;
        Set<String> result = new LinkedHashSet<>();
        if (source instanceof Iterable<?> values) values.forEach(value -> { if (value != null) result.add(String.valueOf(value)); });
        if (source instanceof String text) for (String value : text.split("\\s+")) if (!value.isBlank()) result.add(value);
        if (result.isEmpty() && jwt != null) {
            Object claim = jwt.getClaim("scope");
            if (claim != null) for (String value : claim.toString().split("\\s+")) if (!value.isBlank()) result.add(value);
        }
        return Set.copyOf(result);
    }

    private static String value(Object attribute, JsonWebToken jwt, String claim) {
        if (attribute != null && !String.valueOf(attribute).isBlank()) return String.valueOf(attribute);
        if (jwt == null) return null;
        Object value = jwt.getClaim(claim);
        return value == null ? null : String.valueOf(value);
    }

    private static long number(Object attribute, JsonWebToken jwt, String claim, long fallback) {
        String value = value(attribute, jwt, claim);
        if (value == null) return fallback;
        try { return Long.parseLong(value); } catch (NumberFormatException ignored) { return fallback; }
    }

    private static String normalizeCredentialType(String value) {
        if (value.startsWith("[")) return value.contains("oidc") ? "OIDC" : value.contains("webauthn") ? "PASSKEY" : "PASSWORD";
        return value;
    }

    private static AuthorizationDeniedException denied(ErrorCode code, String message) {
        return new AuthorizationDeniedException(code, message);
    }
}
