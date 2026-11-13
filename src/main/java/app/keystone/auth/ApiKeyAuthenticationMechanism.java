package app.keystone.auth;

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.smallrye.jwt.runtime.auth.JWTAuthMechanism;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.inject.Alternative;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.HashSet;
import java.util.Set;

/** 在保留 Bearer JWT 的同时，为 ApiKey 方案创建统一的 Quarkus SecurityIdentity。 */
@Alternative
@Priority(1)
@ApplicationScoped
public class ApiKeyAuthenticationMechanism implements HttpAuthenticationMechanism {
    private static final String SCHEME = "ApiKey";
    @Inject JWTAuthMechanism jwt;
    @Inject ClientAddressResolver clientAddresses;

    @Override
    public io.smallrye.mutiny.Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager manager) {
        var headers = context.request().headers().getAll("Authorization");
        if (headers.size() > 1) return io.smallrye.mutiny.Uni.createFrom().failure(new io.quarkus.security.AuthenticationFailedException("multiple authorization credentials are not allowed"));
        String header = headers.isEmpty() ? null : headers.get(0);
        if (header == null || !header.regionMatches(true, 0, SCHEME + " ", 0, SCHEME.length() + 1)) {
            return jwt.authenticate(context, manager);
        }
        String value = header.substring(SCHEME.length() + 1).trim();
        if (value.isBlank()) return io.smallrye.mutiny.Uni.createFrom().failure(new io.quarkus.security.AuthenticationFailedException("empty API key"));
        String clientAddress = clientAddresses.resolve(context, context.request().getHeader("X-Forwarded-For"));
        AuthenticationRequest request = io.quarkus.vertx.http.runtime.security.HttpSecurityUtils.setRoutingContextAttribute(new ApiKeyAuthenticationRequest(value, clientAddress), context);
        return manager.authenticate(request);
    }

    @Override
    public io.smallrye.mutiny.Uni<ChallengeData> getChallenge(RoutingContext context) {
        String header = context.request().getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, SCHEME + " ", 0, SCHEME.length() + 1)) {
            return io.smallrye.mutiny.Uni.createFrom().item(new ChallengeData(401, "WWW-Authenticate", SCHEME));
        }
        return jwt.getChallenge(context);
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        Set<Class<? extends AuthenticationRequest>> result = new HashSet<>(jwt.getCredentialTypes());
        result.add(ApiKeyAuthenticationRequest.class);
        return result;
    }

    @Override
    public io.smallrye.mutiny.Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        String header = context.request().getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, SCHEME + " ", 0, SCHEME.length() + 1)) {
            return io.smallrye.mutiny.Uni.createFrom().item(new HttpCredentialTransport(HttpCredentialTransport.Type.AUTHORIZATION, "Authorization", SCHEME));
        }
        return jwt.getCredentialTransport(context);
    }
}
