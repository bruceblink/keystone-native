package app.keystone.auth;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import io.quarkus.security.identity.SecurityIdentity;
import org.eclipse.microprofile.jwt.JsonWebToken;

/** Rejects protected requests after their refresh session has been revoked. */
@Provider
@Priority(Priorities.AUTHENTICATION + 100)
public class AccessSessionFilter implements ContainerRequestFilter {
    @Inject SecurityIdentity identity;
    @Inject SessionRepository sessions;

    @Override
    public void filter(ContainerRequestContext context) {
        if (!(identity.getPrincipal() instanceof JsonWebToken jwt)) return;
        String accessTokenId = jwt.getClaim("jti");
        // JWT 已经通过签名校验后仍必须绑定到活动会话，缺少 jti 时直接拒绝。
        if (accessTokenId == null || accessTokenId.isBlank()) {
            context.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("access token session identifier is required").build());
            return;
        }
        try {
            if (!sessions.isAccessTokenActive(accessTokenId)) context.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("access session is no longer active").build());
        } catch (IllegalStateException e) {
            context.abortWith(Response.status(Response.Status.SERVICE_UNAVAILABLE).entity("authentication state is unavailable").build());
        }
    }
}
