package app.keystone.role;

import app.keystone.ApiResponse;
import app.keystone.ExcelExporter;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.RequiresMfaStepUp;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.NoSuchElementException;

@Path("/v1/roles")
@Produces(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("role")
public class RoleResource {
    @Inject RoleRepository roles;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @RequiresPermission("role:read")
    public ApiResponse<java.util.List<Role>> list() { return ApiResponse.ok(roles.list(context())); }

    /** 返回角色已分配或尚未分配的用户 ID，查询范围由角色资源规则统一限制。 */
    @GET @Path("/{id}/users") @RequiresPermission("role:read")
    public Response users(@PathParam("id") String id, @QueryParam("allocated") @DefaultValue("true") boolean allocated) {
        try { return Response.ok(ApiResponse.ok(roles.userIdsById(context(), id, allocated))).build(); }
        catch (IllegalArgumentException e) { return bad("id must be a UUID"); }
        catch (NoSuchElementException e) { return notFound(); }
    }

    @GET @Path("/export") @Produces(ExcelExporter.CONTENT_TYPE) @RequiresPermission("role:export")
    public Response export() {
        return Response.ok(RoleExcelExporter.export(roles.export(context())))
                .type(ExcelExporter.CONTENT_TYPE)
                .header("Content-Disposition", "attachment; filename=roles.xlsx")
                .build();
    }

    @POST @RequiresPermission("role:create") @RequiresMfaStepUp public Response create(RoleRequest request) { if (request == null) return bad("request body is required"); try { var role = roles.create(context(), request.code(), request.name()); logs.record(actor(), "CREATE", "role", String.valueOf(role.id()), role.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("role:update") @RequiresMfaStepUp public Response update(@PathParam("id") String id, RoleRequest request) { if (request == null) return bad("request body is required"); try { var role = roles.updateById(context(), id, request.name(), request.enabled()); logs.record(actor(), "UPDATE", "role", role.id(), role.code()); return Response.ok(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }
    @PUT @Path("/{id}/permissions") @RequiresPermission("role:manage") @RequiresMfaStepUp public Response permissions(@PathParam("id") String id, PermissionRequest request) { if (request == null) return bad("request body is required"); try { roles.assignPermissionsById(context(), id, request.permissions()); logs.record(actor(), "UPDATE", "role-permission", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }
    /** 原子追加角色成员；成员权限版本在同一事务内递增。 */
    @PUT @Path("/{id}/users") @RequiresPermission("role:assign") @RequiresMfaStepUp
    public Response assignUsers(@PathParam("id") String id, UserAssignmentRequest request) {
        if (request == null || request.userIds() == null) return bad("userIds is required");
        try { roles.assignUsersById(context(), id, request.userIds()); logs.record(actor(), "UPDATE", "role-users", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (NoSuchElementException e) { return notFound(e.getMessage()); }
    }

    /** 原子移除角色成员；重复或不存在的成员保持幂等。 */
    @DELETE @Path("/{id}/users") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("role:assign") @RequiresMfaStepUp
    public Response revokeUsers(@PathParam("id") String id, UserAssignmentRequest request) {
        if (request == null || request.userIds() == null) return bad("userIds is required");
        try { roles.revokeUsersById(context(), id, request.userIds()); logs.record(actor(), "UPDATE", "role-users", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (NoSuchElementException e) { return notFound(e.getMessage()); }
    }

    @DELETE @Path("/{id}") @RequiresPermission("role:delete") @RequiresMfaStepUp public Response delete(@PathParam("id") String id) { try { roles.deleteById(context(), id); logs.record(actor(), "DELETE", "role", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }

    /** 批量删除角色；请求包含非法或不存在目标时全部回滚。 */
    @DELETE @RequiresPermission("role:delete") @RequiresMfaStepUp
    public Response deleteBatch(@QueryParam("ids") String ids) {
        try {
            int deleted = roles.deleteAll(context(), splitIds(ids));
            logs.record(actor(), "DELETE", "roles", null, "batch deleted=" + deleted);
            return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", deleted))).build();
        } catch (IllegalArgumentException e) {
            return bad(e.getMessage());
        } catch (NoSuchElementException e) {
            return notFound();
        }
    }

    private AuthorizationContext context() { return authorization.context(identity); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("role not found")).build(); }
    private static Response notFound(String message) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(message)).build(); }
    private static List<String> splitIds(String raw) { return raw == null ? List.of() : java.util.Arrays.stream(raw.split(",")).map(String::trim).filter(value -> !value.isEmpty()).toList(); }
    public record RoleRequest(String code, String name, Boolean enabled) {}
    public record PermissionRequest(List<String> permissions) {}
    public record UserAssignmentRequest(List<String> userIds) {}
}
