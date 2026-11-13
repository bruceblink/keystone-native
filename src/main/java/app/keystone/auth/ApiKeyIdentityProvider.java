package app.keystone.auth;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import app.keystone.audit.SecurityEventRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.Principal;

@ApplicationScoped
public class ApiKeyIdentityProvider implements IdentityProvider<ApiKeyAuthenticationRequest> {
    @Inject ApiKeyRepository keys;
    @Inject ApiKeyRateLimiter rateLimiter;
    @Inject SecurityEventRepository securityEvents;

    @Override
    public Class<ApiKeyAuthenticationRequest> getRequestType() {
        return ApiKeyAuthenticationRequest.class;
    }

    @Override
    public io.smallrye.mutiny.Uni<SecurityIdentity> authenticate(ApiKeyAuthenticationRequest request, AuthenticationRequestContext context) {
        return context.runBlocking(() -> {
            if (rateLimiter.isBlocked(request.value(), request.clientAddress())) {
                recordEvent(request, "BLOCKED", "API key rate limit exceeded");
                throw new AuthenticationFailedException("API key rate limit exceeded");
            }
            var principal = keys.authenticate(request.value());
            if (principal == null) {
                rateLimiter.recordFailure(request.value(), request.clientAddress());
                recordEvent(request, "FAILURE", "invalid API key");
                throw new AuthenticationFailedException("invalid API key");
            }
            rateLimiter.clear(request.value(), request.clientAddress());
            securityEvents.record("API_KEY_AUTH", principal.username(), "API_KEY", request.clientAddress(), "authentication", "api-key", "SUCCESS", null);
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

    private void recordEvent(ApiKeyAuthenticationRequest request, String outcome, String detail) {
        try { securityEvents.record("API_KEY_AUTH", null, "API_KEY", request.clientAddress(), "authentication", "api-key", outcome, detail); }
        catch (IllegalStateException ignored) { }
    }

    private record ApiKeyPrincipal(String name, String keyId) implements Principal {
        @Override
        public String getName() {
            return name;
        }
    }
}
