package app.keystone.auth;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.Principal;

@ApplicationScoped
public class ApiKeyIdentityProvider implements IdentityProvider<ApiKeyAuthenticationRequest> {
    @Inject ApiKeyRepository keys;

    @Override
    public Class<ApiKeyAuthenticationRequest> getRequestType() {
        return ApiKeyAuthenticationRequest.class;
    }

    @Override
    public io.smallrye.mutiny.Uni<SecurityIdentity> authenticate(ApiKeyAuthenticationRequest request, AuthenticationRequestContext context) {
        return context.runBlocking(() -> {
            var principal = keys.authenticate(request.value());
            if (principal == null) throw new AuthenticationFailedException("invalid API key");
            var builder = QuarkusSecurityIdentity.builder()
                    .setPrincipal(new ApiKeyPrincipal(principal.username(), principal.keyId()))
                    .addAttribute("credentialType", "API_KEY")
                    .addAttribute("credentialId", principal.keyId())
                    .addAttribute("subjectId", principal.subjectId())
                    .addAttribute("userId", principal.userId())
                    .addAttribute("scopes", principal.scopes())
                    ;
            principal.scopes().forEach(builder::addPermissionAsString);
            return builder.build();
        });
    }

    private record ApiKeyPrincipal(String name, String keyId) implements Principal {
        @Override
        public String getName() {
            return name;
        }
    }
}
