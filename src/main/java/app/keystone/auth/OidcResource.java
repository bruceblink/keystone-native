package app.keystone.auth;

import app.keystone.ApiResponse;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/** 暴露 OIDC 授权跳转和回调入口；令牌只通过回调校验后签发。 */
@Path("/v1/auth/oidc")
@Produces(MediaType.APPLICATION_JSON)
public class OidcResource {
    @Inject OidcService oidc;

    @GET
    @Path("/authorize")
    @PermitAll
    @RejectApiKey
    public Response authorize() {
        try {
            return Response.seeOther(oidc.authorize()).build();
        } catch (IllegalArgumentException e) {
            return error(422, "validation_failed", "invalid OIDC authorization request");
        } catch (IllegalStateException e) {
            return error(Response.Status.SERVICE_UNAVAILABLE, "authorization_unavailable", "OIDC authorization is unavailable");
        }
    }

    @GET
    @Path("/callback")
    @PermitAll
    @RejectApiKey
    public Response callback(@QueryParam("code") String code,
                             @QueryParam("state") String state,
                             @QueryParam("error") String providerError) {
        if (providerError != null && !providerError.isBlank()) {
            oidc.cancel(state);
            return error(Response.Status.UNAUTHORIZED, "invalid_credential", "OIDC authorization was not completed");
        }
        try {
            return Response.ok(ApiResponse.ok(oidc.callback(code, state))).build();
        } catch (OidcJwtVerifier.OidcException e) {
            return error(Response.Status.UNAUTHORIZED, "invalid_credential", "OIDC authentication failed");
        } catch (IllegalArgumentException e) {
            return error(422, "validation_failed", "invalid OIDC callback");
        } catch (IllegalStateException e) {
            return error(Response.Status.SERVICE_UNAVAILABLE, "authorization_unavailable", "OIDC authentication is unavailable");
        }
    }

    private static Response error(Response.Status status, String code, String message) {
        return error(status.getStatusCode(), code, message);
    }

    private static Response error(int status, String code, String message) {
        return Response.status(status).entity(ApiResponse.error(code, message)).build();
    }
}
