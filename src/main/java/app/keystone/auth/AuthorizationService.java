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
            return scopes instanceof List<?> values && values.stream().anyMatch(permission::equals);
        }
        try {
            return users.findAuthUserByUsername(identity.getPrincipal().getName()).map(user -> users.permissions(user.id()).contains(permission)).orElse(false);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
