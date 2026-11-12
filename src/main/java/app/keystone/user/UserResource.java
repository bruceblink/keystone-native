package app.keystone.user;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.DataScopeService;
import app.keystone.auth.SessionRepository;
import app.keystone.auth.RequiresPermission;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject SessionRepository sessions;
    @Inject DataScopeService dataScopes;

    @GET @RequiresPermission("user:read")
    public ApiResponse<UserRepository.Page> list(@QueryParam("page") Integer page, @QueryParam("size") Integer size,
                                                  @QueryParam("username") String username, @QueryParam("displayName") String displayName,
                                                  @QueryParam("deptId") Long deptId, @QueryParam("enabled") Boolean enabled) {
        long subjectId = subjectId();
        return ApiResponse.ok(users.list(page == null ? 1 : page, size == null ? 20 : size, username, displayName, deptId, enabled, dataScopes.forUser(subjectId), subjectId));
    }

    @GET @Path("/{id}") @RequiresPermission("user:read")
    public ApiResponse<User> get(@PathParam("id") long id) {
        try { long subjectId = subjectId(); return ApiResponse.ok(users.findPublic(id, dataScopes.forUser(subjectId), subjectId)); }
        catch (java.util.NoSuchElementException e) { throw new NotFoundException("user not found"); }
    }

    @POST @RequiresPermission("user:write")
    public Response create(UserRequest request) {
        if (request == null) return bad("request body is required");
        try {
            long subjectId = subjectId();
            if (!dataScopes.forUser(subjectId).allowsDepartment(request.deptId())) return forbidden();
            var created = users.create(request.username(), request.password(), request.displayName(), request.deptId(), request.postId(), request.email(), request.phoneNumber(), request.sex(), request.avatar(), request.remark(), request.roleCodes());
            logs.record(actor(), "CREATE", "user", String.valueOf(created.id()), created.username());
            return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(created)).build();
        } catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") @RequiresPermission("user:write")
    public Response update(@PathParam("id") long id, UserRequest request) {
        if (request == null) return bad("request body is required");
        try {
            long subjectId = subjectId();
            var scope = dataScopes.forUser(subjectId);
            users.findPublic(id, scope, subjectId);
            if (request.clearDepartment() || request.deptId() != null) {
                Long targetDepartment = request.clearDepartment() ? null : request.deptId();
                if (!scope.allowsDepartment(targetDepartment)) return forbidden();
            }
            var updated = users.updateExtended(id, request.password(), request.displayName(), request.clearDepartment() || request.deptId() != null, request.deptId(), request.postId(), request.email(), request.phoneNumber(), request.sex(), request.avatar(), request.remark(), request.enabled(), request.roleCodes());
            logs.record(actor(), "UPDATE", "user", String.valueOf(id), updated.username());
            return Response.ok(ApiResponse.ok(updated)).build();
        } catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @PUT @Path("/{id}/password") @RequiresPermission("user:write")
    public Response password(@PathParam("id") long id, PasswordRequest request) {
        if (request == null || request.password() == null || request.password().isBlank()) return bad("password is required");
        try { long subjectId = subjectId(); var scope = dataScopes.forUser(subjectId); users.findPublic(id, scope, subjectId); var updated = users.update(id, request.password(), null, null, null, null); sessions.revokeAll(id); logs.record(actor(), "UPDATE", "user-password", String.valueOf(id), null); return Response.ok(ApiResponse.ok(updated)).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @PUT @Path("/{id}/status") @RequiresPermission("user:write")
    public Response status(@PathParam("id") long id, StatusRequest request) {
        if (request == null || request.enabled() == null) return bad("enabled is required");
        try { long subjectId = subjectId(); var scope = dataScopes.forUser(subjectId); users.findPublic(id, scope, subjectId); var updated = users.update(id, null, null, null, request.enabled(), null); if (!request.enabled()) sessions.revokeAll(id); logs.record(actor(), "UPDATE", "user-status", String.valueOf(id), String.valueOf(request.enabled())); return Response.ok(ApiResponse.ok(updated)).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @Path("/{id}") @RequiresPermission("user:write")
    public Response delete(@PathParam("id") long id) {
        try { long subjectId = subjectId(); users.delete(id, dataScopes.forUser(subjectId), subjectId); logs.record(actor(), "DELETE", "user", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @RequiresPermission("user:write")
    public Response deleteBatch(@QueryParam("ids") String ids) {
        if (ids == null || ids.isBlank()) return bad("ids is required");
        try { long subjectId = subjectId(); var values = java.util.Arrays.stream(ids.split(",")).map(String::trim).map(Long::valueOf).toList(); int deleted = users.deleteAll(values, dataScopes.forUser(subjectId), subjectId); logs.record(actor(), "DELETE", "users", ids, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", deleted))).build(); }
        catch (NumberFormatException e) { return bad("ids must be comma separated numbers"); }
    }

    private String actor() { return identity.getPrincipal().getName(); }
    /** 从统一安全身份解析主体，API Key 使用认证阶段写入的 userId，JWT 使用用户名回查。 */
    private long subjectId() {
        Object value = identity.getAttribute("userId");
        if (value instanceof Number number) return number.longValue();
        return users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(() -> new NotAuthorizedException("subject not found")).id();
    }
    private static Response forbidden() { return Response.status(Response.Status.FORBIDDEN).entity(ApiResponse.error("data scope denied")).build(); }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("user not found")).build(); }
    public record UserRequest(String username, String password, String displayName, Long deptId, Long postId, String email, String phoneNumber, Integer sex, String avatar, String remark, Boolean enabled, Boolean clearDept, List<String> roleCodes) {
        public boolean clearDepartment() { return Boolean.TRUE.equals(clearDept); }
    }
    public record PasswordRequest(String password) {}
    public record StatusRequest(Boolean enabled) {}
}
