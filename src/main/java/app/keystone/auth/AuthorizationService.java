package app.keystone.auth;

import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;

@ApplicationScoped
public class AuthorizationService {
    @Inject UserRepository users;

    public boolean allowed(SecurityIdentity identity, String permission) {
        if (identity == null || identity.isAnonymous() || permission == null || permission.isBlank()) return false;
        Object credentialType = identity.getAttribute("credentialType");
        if ("API_KEY".equals(credentialType)) {
            Object scopes = identity.getAttribute("scopes");
            Object userId = identity.getAttribute("userId");
            if (!(userId instanceof Number number) || !(scopes instanceof List<?> values) || values.stream().noneMatch(permission::equals)) return false;
            // API Key 权限必须同时满足签发范围和主体当前权限，角色变更会立即收紧结果。
            return users.permissions(number.longValue()).contains(permission);
        }
        return users.findAuthUserByUsername(identity.getPrincipal().getName()).map(user -> users.permissions(user.id()).contains(permission)).orElse(false);
    }
}
