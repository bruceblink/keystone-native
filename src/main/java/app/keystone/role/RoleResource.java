package app.keystone.role;

import app.keystone.ApiResponse;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/v1/roles")
@Produces(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class RoleResource {
    @Inject RoleRepository roles;

    @GET
    public ApiResponse<java.util.List<Role>> list() { return ApiResponse.ok(roles.list()); }
}
