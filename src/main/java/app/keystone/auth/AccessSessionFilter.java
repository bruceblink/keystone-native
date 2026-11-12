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
        String accessTokenId = null;
        if (identity.getPrincipal() instanceof JsonWebToken jwt) accessTokenId = jwt.getClaim("jti");
        if (accessTokenId != null && !sessions.isAccessTokenActive(accessTokenId)) {
            context.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("access session is no longer active").build());
        }
    }
}
