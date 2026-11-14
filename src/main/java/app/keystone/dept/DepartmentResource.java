package app.keystone.dept;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import jakarta.inject.Inject;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/departments")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class DepartmentResource {
    @Inject DepartmentRepository departments;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @RequiresPermission("department:read")
    public ApiResponse<List<Department>> list() { return ApiResponse.ok(departments.list(context())); }
    @GET @Path("/dropdown") @RequiresPermission("department:read")
    public ApiResponse<List<Department>> dropdown() { return ApiResponse.ok(departments.list(context())); }

    @POST @RequiresPermission("department:create")
    public Response create(DepartmentRequest request) {
        if (request == null) return bad("request body is required");
        try { var created = departments.create(context(), request.code(), request.name(), request.parentId(), request.sortOrder()); logs.record(context(), "CREATE", "department", String.valueOf(created.id()), created.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(created)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") @RequiresPermission("department:update")
    public Response update(@PathParam("id") String id, DepartmentRequest request) {
        if (request == null) return bad("request body is required");
        try { var updated = departments.update(context(), id, request.name(), request.parentId(), request.sortOrder(), request.enabled()); logs.record(context(), "UPDATE", "department", String.valueOf(id), updated.code()); return Response.ok(ApiResponse.ok(updated)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @Path("/{id}") @RequiresPermission("department:delete")
    public Response delete(@PathParam("id") String id) {
        try { departments.delete(context(), id); logs.record(context(), "DELETE", "department", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("department not found")).build(); }
    public record DepartmentRequest(String code, String name, String parentId, Integer sortOrder, Boolean enabled) {}
    private String actor() { return identity.getPrincipal().getName(); }
    private AuthorizationContext context() { return authorization.context(identity); }
}
