package app.keystone.auth;

import app.keystone.ApiResponse;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/** 发布当前 JWT 验证公钥；root path 为 /api 时访问路径是 /api/.well-known/jwks.json。 */
@Path("/.well-known/jwks.json")
@Produces(MediaType.APPLICATION_JSON)
@PermitAll
public class JwkSetResource {
    @Inject JwkSetService keys;

    @GET
    public Response get() {
        try {
            return Response.ok(keys.current())
                    .header("Cache-Control", "public, max-age=60, must-revalidate")
                    .build();
        } catch (IllegalStateException e) {
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity(ApiResponse.error("JWT key set is unavailable"))
                    .build();
        }
    }
}
