package app.keystone.user;

import app.keystone.ApiResponse;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class UserResource {
    @Inject UserRepository users;
    @GET
    public ApiResponse<UserRepository.Page> list(@QueryParam("page") Integer page, @QueryParam("size") Integer size) {
        return ApiResponse.ok(users.list(page == null ? 1 : page, size == null ? 20 : size));
    }

    @POST
    @RolesAllowed("ADMIN")
    public Response create(UserRequest request) {
        if (request == null) return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("request body is required")).build();
        try { return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(users.create(request.username(), request.password(), request.displayName(), request.roleCodes()))).build(); }
        catch (IllegalArgumentException e) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(e.getMessage())).build(); }
    }

    @PUT @Path("/{id}")
    @RolesAllowed("ADMIN")
    public Response update(@PathParam("id") long id, UserRequest request) {
        if (request == null) return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("request body is required")).build();
        try { return Response.ok(ApiResponse.ok(users.update(id, request.password(), request.displayName(), request.enabled(), request.roleCodes()))).build(); }
        catch (IllegalArgumentException e) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (java.util.NoSuchElementException e) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("user not found")).build(); }
    }

    @DELETE @Path("/{id}")
    @RolesAllowed("ADMIN")
    public Response delete(@PathParam("id") long id) {
        try { users.delete(id); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (java.util.NoSuchElementException e) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("user not found")).build(); }
    }

    public record UserRequest(String username, String password, String displayName, Boolean enabled, List<String> roleCodes) {}
}
