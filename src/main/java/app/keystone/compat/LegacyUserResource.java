package app.keystone.compat;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.DataScopeService;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.RequiresMfaStepUp;
import app.keystone.auth.RejectApiKey;
import app.keystone.auth.SessionRepository;
import app.keystone.role.RoleRepository;
import app.keystone.user.User;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

@Path("/system/users")
@Produces(MediaType.APPLICATION_JSON)
public class LegacyUserResource {
    @Inject UserRepository users;
    @Inject RoleRepository roles;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject DataScopeService dataScopes;
    @Inject SessionRepository sessions;

    @GET @RequiresPermission("user:read")
    public ApiResponse<UserRepository.Page> list(@QueryParam("pageNum") Integer pageNum, @QueryParam("pageSize") Integer pageSize, @QueryParam("username") String username, @QueryParam("nickname") String nickname, @QueryParam("deptId") Long deptId, @QueryParam("status") Integer status) {
        long subjectId = subjectId();
        return ApiResponse.ok(users.list(pageNum == null ? 1 : pageNum, pageSize == null ? 20 : pageSize, username, nickname, deptId, status == null ? null : status == 1, dataScopes.forUser(subjectId), subjectId));
    }

    @GET @Path("/excel") @RequiresPermission("user:read")
    public Response export(@QueryParam("username") String username, @QueryParam("nickname") String nickname) { long subjectId = subjectId(); var page = users.list(1, 100, username, nickname, null, null, dataScopes.forUser(subjectId), subjectId); var rows = new java.util.ArrayList<String[]>(); rows.add(new String[]{"id", "username", "displayName", "email", "phoneNumber", "enabled"}); for (User user : page.items()) rows.add(new String[]{String.valueOf(user.id()), user.username(), user.displayName(), user.email(), user.phoneNumber(), String.valueOf(user.enabled())}); return CsvExport.response("users.csv", rows); }
    @GET @Path("/excelTemplate") @RequiresPermission("user:read")
    public Response template() { return CsvExport.response("users-template.csv", java.util.Collections.singletonList(new String[]{"username", "password", "displayName", "email", "phoneNumber", "roleCode"})); }
    @POST @Path("/excel") @RequiresPermission("user:write") @RequiresMfaStepUp @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response importCsv(@RestForm("file") FileUpload file) { if (file == null) return bad("file is required"); long subjectId = subjectId(); var scope = dataScopes.forUser(subjectId); if (!scope.allowsDepartment(null)) return forbidden(); int imported = 0; try { for (String line : Files.readAllLines(file.uploadedFile())) { if (line.isBlank() || line.toLowerCase().startsWith("username,")) continue; String[] columns = line.split(",", -1); if (columns.length < 3) continue; users.create(columns[0].trim(), columns[1].trim(), columns[2].trim(), null, null, columns.length > 3 ? columns[3].trim() : null, columns.length > 4 ? columns[4].trim() : null, null, null, null, columns.length > 5 && !columns[5].isBlank() ? List.of(columns[5].trim()) : List.of("USER")); imported++; } return Response.ok(ApiResponse.ok(java.util.Map.of("imported", imported))).build(); } catch (Exception e) { return bad("invalid user import file"); } }

    @GET @Path("/{id}") @RequiresPermission("user:read")
    public ApiResponse<User> get(@PathParam("id") long id) { try { long subjectId = subjectId(); return ApiResponse.ok(users.findPublic(id, dataScopes.forUser(subjectId), subjectId)); } catch (java.util.NoSuchElementException e) { throw new NotFoundException("user not found"); } }

    @POST @RequiresPermission("user:write") @RequiresMfaStepUp @Consumes(MediaType.APPLICATION_JSON)
    public Response create(UserCommand request) {
        if (request == null) return bad("request body is required");
        try { long subjectId = subjectId(); if (!dataScopes.forUser(subjectId).allowsDepartment(request.deptId)) return forbidden(); var value = users.create(request.username, request.password, request.displayNameValue(), request.deptId, request.postId, request.email, request.phoneNumber, request.sex, request.avatar, request.remark, roleCodes(request)); logs.record(actor(), "CREATE", "user", String.valueOf(value.id()), value.username()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(value)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") @RequiresPermission("user:write") @RequiresMfaStepUp @Consumes(MediaType.APPLICATION_JSON)
    public Response update(@PathParam("id") long id, UserCommand request) {
        if (request == null) return bad("request body is required");
        try { long subjectId = subjectId(); var scope = dataScopes.forUser(subjectId); users.findPublic(id, scope, subjectId); if (request.clearDeptValue() || request.deptId != null) { Long targetDepartment = request.clearDeptValue() ? null : request.deptId; if (!scope.allowsDepartment(targetDepartment)) return forbidden(); } var value = users.updateExtended(id, request.password, request.displayName, request.clearDeptValue() || request.deptId != null, request.deptId, request.postId, request.email, request.phoneNumber, request.sex, request.avatar, request.remark, request.enabledValue(), roleCodesOrNull(request)); logs.record(actor(), "UPDATE", "user", String.valueOf(id), value.username()); return Response.ok(ApiResponse.ok(value)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound("user not found"); }
    }

    @DELETE @Path("/{ids}") @RequiresPermission("user:write") @RequiresMfaStepUp @RejectApiKey
    public Response delete(@PathParam("ids") String ids) { try { long subjectId = subjectId(); var values = parseIds(ids); int deleted = users.deleteAll(values, dataScopes.forUser(subjectId), subjectId); logs.record(actor(), "DELETE", "users", ids, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", deleted))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }

    @PUT @Path("/{id}/password") @RequiresPermission("user:write") @RequiresMfaStepUp @RejectApiKey @Consumes(MediaType.APPLICATION_JSON)
    public Response password(@PathParam("id") long id, PasswordCommand request) { if (request == null || request.passwordValue() == null || request.passwordValue().isBlank()) return bad("password is required"); try { long subjectId = subjectId(); users.findPublic(id, dataScopes.forUser(subjectId), subjectId); var updated = users.update(id, request.passwordValue(), null, null, null, null); sessions.revokeAll(id); return Response.ok(ApiResponse.ok(updated)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound("user not found"); } }

    @PUT @Path("/{id}/status") @RequiresPermission("user:write") @RequiresMfaStepUp @Consumes(MediaType.APPLICATION_JSON)
    public Response status(@PathParam("id") long id, StatusCommand request) { if (request == null || request.enabledValue() == null) return bad("status is required"); try { long subjectId = subjectId(); users.findPublic(id, dataScopes.forUser(subjectId), subjectId); var updated = users.update(id, null, null, null, request.enabledValue(), null); if (!request.enabledValue()) sessions.revokeAll(id); return Response.ok(ApiResponse.ok(updated)).build(); } catch (java.util.NoSuchElementException e) { return notFound("user not found"); } }

    private List<String> roleCodes(UserCommand request) { List<String> codes = roleCodesOrNull(request); return codes == null || codes.isEmpty() ? List.of("USER") : codes; }
    private List<String> roleCodesOrNull(UserCommand request) { if (request.roleCodes != null && !request.roleCodes.isEmpty()) return request.roleCodes; if (request.roleCode != null && !request.roleCode.isBlank()) return List.of(request.roleCode); if (request.roleId != null) return List.of(roles.findById(request.roleId).code()); return null; }
    private String actor() { return identity.getPrincipal().getName(); }
    /** 统一从安全身份得到当前用户，保证兼容路由也使用相同数据范围。 */
    private long subjectId() { Object value = identity.getAttribute("userId"); if (value instanceof Number number) return number.longValue(); return users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(() -> new NotAuthorizedException("subject not found")).id(); }
    private static Response forbidden() { return Response.status(Response.Status.FORBIDDEN).entity(ApiResponse.error("data scope denied")).build(); }
    private static List<Long> parseIds(String ids) { if (ids == null || ids.isBlank()) throw new IllegalArgumentException("ids is required"); try { return Arrays.stream(ids.split(",")).map(String::trim).map(Long::valueOf).toList(); } catch (NumberFormatException e) { throw new IllegalArgumentException("ids must be comma separated numbers"); } }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound(String message) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(message)).build(); }

    public record UserCommand(String username, String password, String displayName, String nickname, Long deptId, Long postId, Long roleId, String roleCode, List<String> roleCodes, String email, String phoneNumber, Integer sex, String avatar, String remark, Boolean enabled, Integer status, Boolean clearDept) {
        private String displayNameValue() { return displayName == null ? nickname : displayName; }
        private Boolean enabledValue() { return enabled == null ? (status == null ? null : status == 1) : enabled; }
        private boolean clearDeptValue() { return Boolean.TRUE.equals(clearDept); }
    }
    public record PasswordCommand(String password, String newPassword) { private String passwordValue() { return password == null ? newPassword : password; } }
    public record StatusCommand(Boolean enabled, Integer status) { private Boolean enabledValue() { return enabled == null ? (status == null ? null : status == 1) : enabled; } }
}
