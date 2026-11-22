package app.keystone.role;

import app.keystone.ErrorCode;

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

    /** page/size 或筛选条件传入时返回 {items,page,size,total}；省略时保留旧数组响应。 */
    @GET @RequiresPermission("role:read")
    public ApiResponse<?> list(
            @QueryParam("page") Integer page,
            @QueryParam("size") Integer size,
            @QueryParam("keyword") String keyword,
            @QueryParam("status") String status) {
        if (page == null && size == null && !hasFilter(keyword, status)) {
            return ApiResponse.ok(roles.list(context()));
        }
        return ApiResponse.ok(roles.list(context(), page == null ? 1 : page, size == null ? 20 : size, keyword, status));
    }

    /** 未传 page/size 时保留数组响应；分页请求返回当前页和筛选后的总数。 */
    @GET @Path("/{id}/users") @RequiresPermission("role:read")
    public Response users(
            @PathParam("id") String id,
            @QueryParam("allocated") @DefaultValue("true") boolean allocated,
            @QueryParam("username") String username,
            @QueryParam("phoneNumber") String phoneNumber,
            @QueryParam("include") String include,
            @QueryParam("page") String pageParam,
            @QueryParam("size") String sizeParam) {
        try {
            if (pageParam != null || sizeParam != null) {
                int currentPage = positiveIntOrOne(pageParam);
                int currentSize = sizeParam == null ? 20 : Math.min(100, positiveIntOrOne(sizeParam));
                Object result = "identity".equals(include)
                        ? roles.membersPageById(context(), id, allocated, username, phoneNumber, currentPage, currentSize)
                        : roles.userIdsPageById(context(), id, allocated, username, phoneNumber, currentPage, currentSize);
                return Response.ok(ApiResponse.ok(result)).build();
            }

            Object members = "identity".equals(include)
                    ? roles.membersById(context(), id, allocated, username, phoneNumber)
                    : roles.userIdsById(context(), id, allocated, username, phoneNumber);
            return Response.ok(ApiResponse.ok(members)).build();
        }
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

    @POST @RequiresPermission("role:create") @RequiresMfaStepUp public Response create(RoleRequest request) { if (request == null) return bad("request body is required"); try { var role = roles.create(context(), request.code(), request.name(), request.enabled()); logs.record(actor(), "CREATE", "role", String.valueOf(role.id()), role.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("role:update") @RequiresMfaStepUp public Response update(@PathParam("id") String id, RoleRequest request) { if (request == null) return bad("request body is required"); try { var role = roles.updateById(context(), id, request.name(), request.enabled()); logs.record(actor(), "UPDATE", "role", role.id(), role.code()); return Response.ok(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }
    @PUT @Path("/{id}/permissions") @RequiresPermission("role:manage") @RequiresMfaStepUp public Response permissions(@PathParam("id") String id, PermissionRequest request) { if (request == null) return bad("request body is required"); try { roles.assignPermissionsById(context(), id, request.permissions()); logs.record(actor(), "UPDATE", "role-permission", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build(); } catch (IllegalArgumentException e) { return invalidPermission(e); } catch (NoSuchElementException e) { return notFound(); } }
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

    @DELETE @Path("/{id}") @RequiresPermission("role:delete") @RequiresMfaStepUp public Response delete(@PathParam("id") String id) { try { roles.deleteById(context(), id); logs.record(actor(), "DELETE", "role", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (ProtectedSystemRoleException e) { return systemRoleProtected(); } catch (RoleHasAssignedUsersException e) { return roleHasUsers(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }

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
        } catch (ProtectedSystemRoleException e) {
            return systemRoleProtected();
        } catch (RoleHasAssignedUsersException e) {
            return roleHasUsers();
        }
    }

    private AuthorizationContext context() { return authorization.context(identity); }
    private String actor() { return identity.getPrincipal().getName(); }
    /** 分页参数无效或非正数时归一为一，与 Phoenix REST 的行为一致。 */
    private static int positiveIntOrOne(String raw) {
        if (raw == null) return 1;
        try {
            return Math.max(1, Integer.parseInt(raw));
        } catch (NumberFormatException e) {
            return 1;
        }
    }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(ErrorCode.VALIDATION_FAILED, message)).build(); }
    private static Response invalidPermission(IllegalArgumentException error) {
        return error.getMessage() != null && error.getMessage().startsWith("unknown permission")
                ? Response.status(422).entity(ApiResponse.error(ErrorCode.PERMISSION_NOT_FOUND, "permission not found")).build()
                : bad(error.getMessage());
    }
    private static Response systemRoleProtected() { return ApiResponse.response(422, ErrorCode.ROLE_PROTECTED, "管理员角色不能删除"); }
    private static Response roleHasUsers() { return ApiResponse.response(422, ErrorCode.ROLE_HAS_MEMBERS, "角色存在用户，不能删除"); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, "role not found")).build(); }
    private static Response notFound(String message) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, message)).build(); }
    private static List<String> splitIds(String raw) { return raw == null ? List.of() : java.util.Arrays.stream(raw.split(",")).map(String::trim).filter(value -> !value.isEmpty()).toList(); }
    private static boolean hasFilter(String... values) { return java.util.Arrays.stream(values).anyMatch(value -> value != null && !value.isBlank()); }
    public record RoleRequest(String code, String name, Boolean enabled) {}
    public record PermissionRequest(List<String> permissions) {}
    public record UserAssignmentRequest(List<String> userIds) {}
}
