package app.keystone.compat;

import app.keystone.ApiResponse;
import app.keystone.auth.RequiresPermission;
import app.keystone.audit.OperationLogRepository;
import app.keystone.role.Role;
import app.keystone.role.RoleRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;

@Path("/system/role")
@Produces(MediaType.APPLICATION_JSON)
public class LegacyRoleResource {
    @Inject RoleRepository roles;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET @Path("/list") @RequiresPermission("role:read") public ApiResponse<Page> list(@QueryParam("pageNum") Integer page, @QueryParam("pageSize") Integer size) { var all = roles.list(); int p = Math.max(1, page == null ? 1 : page), s = Math.min(100, Math.max(1, size == null ? 20 : size)); int from = Math.min(all.size(), (p - 1) * s), to = Math.min(all.size(), from + s); return ApiResponse.ok(new Page(all.subList(from, to), p, s, all.size())); }
    @POST @Path("/export") @RequiresPermission("role:read") public Response export() { var rows = new java.util.ArrayList<String[]>(); rows.add(new String[]{"id", "code", "name", "enabled", "dataScope"}); for (Role role : roles.list()) rows.add(new String[]{String.valueOf(role.id()), role.code(), role.name(), String.valueOf(role.enabled()), role.dataScope()}); return CsvExport.response("roles.csv", rows); }
    @GET @Path("/{id}") @RequiresPermission("role:read") public ApiResponse<Role> get(@PathParam("id") long id) { return ApiResponse.ok(roles.findById(id)); }
    @POST @RequiresPermission("role:write") @Consumes(MediaType.APPLICATION_JSON) public Response create(RoleCommand request) { if (request == null) return bad("request body is required"); try { var role = roles.create(request.codeValue(), request.nameValue()); logs.record(actor(), "CREATE", "role", String.valueOf(role.id()), role.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(role)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @RequiresPermission("role:write") @Consumes(MediaType.APPLICATION_JSON) public Response update(RoleCommand request) { if (request == null || request.codeValue() == null) return bad("code is required"); try { var role = roles.updateExtended(request.codeValue(), request.nameValue(), request.enabledValue(), request.dataScope, request.deptScope); logs.record(actor(), "UPDATE", "role", String.valueOf(role.id()), role.code()); return Response.ok(ApiResponse.ok(role)).build(); } catch (java.util.NoSuchElementException e) { return notFound("role not found"); } }
    @DELETE @Path("/{ids}") @RequiresPermission("role:write") public Response delete(@PathParam("ids") String ids) { try { int count = 0; for (Long id : parseIds(ids)) { roles.delete(roles.findById(id).code()); count++; } return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", count))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}/status") @RequiresPermission("role:write") @Consumes(MediaType.APPLICATION_JSON) public Response status(@PathParam("id") long id, StatusCommand request) { if (request == null || request.enabledValue() == null) return bad("status is required"); var role = roles.findById(id); return Response.ok(ApiResponse.ok(roles.update(role.code(), null, request.enabledValue()))).build(); }
    @PUT @Path("/{id}/dataScope") @RequiresPermission("role:write") @Consumes(MediaType.APPLICATION_JSON) public Response dataScope(@PathParam("id") long id, DataScopeCommand request) { if (request == null || request.dataScope == null) return bad("dataScope is required"); var role = roles.findById(id); return Response.ok(ApiResponse.ok(roles.updateExtended(role.code(), null, null, request.dataScope, request.deptScope))).build(); }
    @GET @Path("/{id}/allocated/list") @RequiresPermission("role:read") public ApiResponse<List<Long>> allocated(@PathParam("id") long id) { return ApiResponse.ok(roles.userIds(roles.findById(id).code(), true)); }
    @GET @Path("/{id}/unallocated/list") @RequiresPermission("role:read") public ApiResponse<List<Long>> unallocated(@PathParam("id") long id) { return ApiResponse.ok(roles.userIds(roles.findById(id).code(), false)); }
    @POST @Path("/{id}/users/{userIds}/grant/bulk") @RequiresPermission("role:write") public Response grant(@PathParam("id") long id, @PathParam("userIds") String userIds) { var role = roles.findById(id); roles.assignUsers(role.code(), parseIds(userIds)); return Response.ok(ApiResponse.ok(java.util.Map.of("granted", true))).build(); }
    @DELETE @Path("/users/{userIds}/grant/bulk") @RequiresPermission("role:write") public Response revoke(@QueryParam("roleId") Long roleId, @PathParam("userIds") String userIds) { if (roleId == null) return bad("roleId is required"); var role = roles.findById(roleId); roles.revokeUsers(role.code(), parseIds(userIds)); return Response.ok(ApiResponse.ok(java.util.Map.of("revoked", true))).build(); }

    private String actor() { return identity.getPrincipal().getName(); }
    private static List<Long> parseIds(String ids) { try { return Arrays.stream(ids.split(",")).map(String::trim).map(Long::valueOf).toList(); } catch (Exception e) { throw new IllegalArgumentException("ids must be comma separated numbers"); } }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound(String message) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(message)).build(); }
    public record Page(List<Role> items, int page, int size, long total) {}
    public record RoleCommand(Long id, String code, String roleKey, String name, String roleName, Boolean enabled, Integer status, String dataScope, String deptScope) { String codeValue() { return code == null ? roleKey : code; } String nameValue() { return name == null ? roleName : name; } Boolean enabledValue() { return enabled == null ? (status == null ? null : status == 1) : enabled; } }
    public record StatusCommand(Boolean enabled, Integer status) { Boolean enabledValue() { return enabled == null ? (status == null ? null : status == 1) : enabled; } }
    public record DataScopeCommand(String dataScope, String deptScope) {}
}
