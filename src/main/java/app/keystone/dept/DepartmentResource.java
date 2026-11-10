package app.keystone.dept;

import app.keystone.ApiResponse;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/departments")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class DepartmentResource {
    @Inject DepartmentRepository departments;

    @GET public ApiResponse<List<Department>> list() { return ApiResponse.ok(departments.list()); }

    @POST @RolesAllowed("ADMIN")
    public Response create(DepartmentRequest request) {
        if (request == null) return bad("request body is required");
        try { return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(departments.create(request.code(), request.name(), request.parentId(), request.sortOrder()))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") @RolesAllowed("ADMIN")
    public Response update(@PathParam("id") long id, DepartmentRequest request) {
        if (request == null) return bad("request body is required");
        try { return Response.ok(ApiResponse.ok(departments.update(id, request.name(), request.parentId(), request.sortOrder(), request.enabled()))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @Path("/{id}") @RolesAllowed("ADMIN")
    public Response delete(@PathParam("id") long id) {
        try { departments.delete(id); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("department not found")).build(); }
    public record DepartmentRequest(String code, String name, Long parentId, Integer sortOrder, Boolean enabled) {}
}
