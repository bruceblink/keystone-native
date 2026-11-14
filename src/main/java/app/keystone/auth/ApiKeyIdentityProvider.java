package app.keystone.auth;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import app.keystone.audit.SecurityEventRepository;
import app.keystone.audit.SecurityObservability;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.Principal;

@ApplicationScoped
public class ApiKeyIdentityProvider implements IdentityProvider<ApiKeyAuthenticationRequest> {
    @Inject ApiKeyRepository keys;
    @Inject ApiKeyRateLimiter rateLimiter;
    @Inject SecurityEventRepository securityEvents;
    @Inject SecurityObservability securityObservability;

    @Override
    public Class<ApiKeyAuthenticationRequest> getRequestType() {
        return ApiKeyAuthenticationRequest.class;
    }

    @Override
    public io.smallrye.mutiny.Uni<SecurityIdentity> authenticate(ApiKeyAuthenticationRequest request, AuthenticationRequestContext context) {
        return context.runBlocking(() -> {
            if (rateLimiter.isBlocked(request.value(), request.clientAddress())) {
                securityObservability.apiKeyFailure(true);
                recordEvent(request, "BLOCKED", "API key rate limit exceeded");
                throw new AuthenticationFailedException("API key rate limit exceeded");
            }
            var principal = keys.authenticate(request.value());
            if (principal == null) {
                securityObservability.apiKeyFailure(rateLimiter.recordFailure(request.value(), request.clientAddress()));
                recordEvent(request, "FAILURE", "invalid API key");
                throw new AuthenticationFailedException("invalid API key");
            }
            try { rateLimiter.clear(request.value(), request.clientAddress()); }
            catch (IllegalStateException e) { recordEvent(request, principal.username(), principal.keyId(), "RATE_LIMIT_CLEAR_FAILED", "API key rate-limit cleanup failed"); }
            recordEvent(request, principal.username(), principal.keyId(), "SUCCESS", null,
                    new SecurityEventRepository.Context(null, String.join(" ", principal.scopes()), null));
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
        recordEvent(request, null, null, outcome, detail, SecurityEventRepository.Context.empty());
    }

    private void recordEvent(ApiKeyAuthenticationRequest request, String actor, String credentialId, String outcome, String detail) {
        recordEvent(request, actor, credentialId, outcome, detail, SecurityEventRepository.Context.empty());
    }

    private void recordEvent(ApiKeyAuthenticationRequest request, String actor, String credentialId, String outcome,
                             String detail, SecurityEventRepository.Context eventContext) {
        try { securityEvents.record("API_KEY_AUTH", actor, "API_KEY", credentialId, request.clientAddress(), "authentication", "api-key", outcome, eventContext, detail); }
        catch (IllegalStateException ignored) { }
    }

    private record ApiKeyPrincipal(String name, String keyId) implements Principal {
        @Override
        public String getName() {
            return name;
        }
    }
}
