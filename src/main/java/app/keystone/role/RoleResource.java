package app.keystone.role;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.RequiresMfaStepUp;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.NoSuchElementException;

@Path("/v1/roles")
@Produces(MediaType.APPLICATION_JSON)
public class RoleResource {
    @Inject RoleRepository roles;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET @RequiresPermission("role:read")
    public ApiResponse<java.util.List<Role>> list() { return ApiResponse.ok(roles.list()); }

    @POST @RequiresPermission("role:create") @RequiresMfaStepUp public Response create(RoleRequest request) { if (request == null) return bad("request body is required"); try { var role = roles.create(request.code(), request.name()); logs.record(actor(), "CREATE", "role", String.valueOf(role.id()), role.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("role:update") @RequiresMfaStepUp public Response update(@PathParam("id") String id, RoleRequest request) { if (request == null) return bad("request body is required"); try { var role = roles.updateById(id, request.name(), request.enabled()); logs.record(actor(), "UPDATE", "role", role.id(), role.code()); return Response.ok(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }
    @PUT @Path("/{id}/permissions") @RequiresPermission("role:manage") @RequiresMfaStepUp public Response permissions(@PathParam("id") String id, PermissionRequest request) { if (request == null) return bad("request body is required"); try { roles.assignPermissionsById(id, request.permissions()); logs.record(actor(), "UPDATE", "role-permission", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }
    @DELETE @Path("/{id}") @RequiresPermission("role:delete") @RequiresMfaStepUp public Response delete(@PathParam("id") String id) { try { roles.deleteById(id); logs.record(actor(), "DELETE", "role", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }

    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("role not found")).build(); }
    public record RoleRequest(String code, String name, Boolean enabled) {}
    public record PermissionRequest(List<String> permissions) {}
}
