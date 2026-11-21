package app.keystone.user;

import app.keystone.ErrorCode;

import app.keystone.ApiResponse;
import app.keystone.ExcelExporter;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.SessionRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.RejectApiKey;
import app.keystone.auth.RequiresMfaStepUp;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;
import java.util.List;

@Path("/v1/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject SessionRepository sessions;
    @Inject AuthorizationService authorization;
    @Inject ObjectMapper objectMapper;

    @GET @RequiresPermission("user:read")
    public ApiResponse<UserRepository.Page> list(@QueryParam("page") Integer page, @QueryParam("size") Integer size,
                                                  @QueryParam("username") String username, @QueryParam("displayName") String displayName,
                                                  @QueryParam("deptId") String deptId, @QueryParam("enabled") Boolean enabled) {
        return ApiResponse.ok(users.list(context(), page == null ? 1 : page, size == null ? 20 : size, username, displayName, deptId, enabled));
    }

    @GET @Path("/export") @Produces(ExcelExporter.CONTENT_TYPE) @RequiresPermission("user:export")
    public Response export(@QueryParam("username") String username, @QueryParam("displayName") String displayName,
                           @QueryParam("deptId") String deptId, @QueryParam("enabled") Boolean enabled) {
        try {
            byte[] workbook = UserExcelExporter.export(users.export(context(), username, displayName, deptId, enabled));
            return Response.ok(workbook).type(ExcelExporter.CONTENT_TYPE)
                    .header("Content-Disposition", "attachment; filename=users.xlsx")
                    .build();
        } catch (IllegalArgumentException e) {
            return bad(e.getMessage());
        }
    }

    /** 从 XLSX 第一张工作表逐行创建用户；失败行返回行号和脱敏原因。 */
    @POST @Path("/import") @Consumes(MediaType.MULTIPART_FORM_DATA)
    @RequiresPermission("user:import") @RequiresMfaStepUp(enforce = true) @RejectApiKey
    public Response importUsers(@RestForm("file") FileUpload file) {
        if (file == null || file.uploadedFile() == null) return bad("file is required");
        try {
            var records = UserExcelImporter.read(file.uploadedFile(), file.fileName());
            int success = 0;
            List<ImportFailure> failures = new java.util.ArrayList<>();
            AuthorizationContext authorizationContext = context();
            for (var record : records) {
                try {
                    var created = users.importUser(authorizationContext, record);
                    logs.record(authorizationContext, "CREATE", "user", String.valueOf(created.id()), created.username());
                    success++;
                } catch (RuntimeException error) {
                    failures.add(new ImportFailure(record.row(), record.username(), importFailure(error), importFailureCode(error)));
                }
            }
            return Response.ok(ApiResponse.ok(new ImportResult(records.size(), success, failures))).build();
        } catch (IllegalArgumentException e) {
            return bad(e.getMessage());
        }
    }

    @GET @Path("/{id}") @RequiresPermission("user:read")
    public ApiResponse<User> get(@PathParam("id") String id) {
        try { return ApiResponse.ok(users.findPublic(context(), id)); }
        catch (java.util.NoSuchElementException e) { throw new NotFoundException("user not found"); }
    }

    @POST @RequiresPermission("user:create") @RequiresMfaStepUp
    public Response create(UserRequest request) {
        if (request == null) return bad("request body is required");
        try {
            var created = users.create(context(), request.username(), request.password(), request.displayName(), request.deptId(), request.postId(), request.email(), request.phoneNumber(), request.sex(), request.avatar(), request.remark(), request.enabled(), request.roleCodes());
            logs.record(context(), "CREATE", "user", String.valueOf(created.id()), created.username());
            return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(created)).build();
        } catch (PasswordPolicyException e) { return passwordPolicyError(e); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") @RequiresPermission("user:update") @RequiresMfaStepUp
    public Response update(@PathParam("id") String id,
                           @Schema(implementation = UserRequest.class) JsonNode body) {
        if (body == null || !body.isObject()) return bad("request body is required");
        UserRequest request;
        try {
            request = objectMapper.treeToValue(body, UserRequest.class);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            return bad("request body is invalid");
        }
        try {
            var fields = new UserRepository.UpdateFieldPresence(body.has("postId"), body.has("email"),
                    body.has("phoneNumber"), body.has("sex"), body.has("avatar"), body.has("remark"));
            var updated = users.updateExtended(context(), id, request.password(), request.displayName(),
                    request.clearDepartment() || request.deptId() != null, request.deptId(), request.postId(),
                    request.email(), request.phoneNumber(), request.sex(), request.avatar(), request.remark(),
                    request.enabled(), request.roleCodes(), fields);
            // 通用编辑显式停用账号后，统一撤销其活动会话和刷新令牌。
            if (Boolean.FALSE.equals(request.enabled())) sessions.revokeAll(id);
            logs.record(context(), "UPDATE", "user", String.valueOf(id), updated.username());
            return Response.ok(ApiResponse.ok(updated)).build();
        } catch (PasswordPolicyException e) { return passwordPolicyError(e); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @PUT @Path("/{id}/password") @RequiresPermission("user:reset-password") @RequiresMfaStepUp @RejectApiKey
    public Response password(@PathParam("id") String id, PasswordRequest request) {
        if (request == null || request.password() == null || request.password().isBlank()) return passwordRequired();
        try { var updated = users.updatePassword(context(), id, request.password()); sessions.revokeAll(id); logs.record(context(), "UPDATE", "user-password", id, null); return Response.ok(ApiResponse.ok(updated)).build(); }
        catch (PasswordPolicyException e) { return passwordPolicyError(e); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @PUT @Path("/{id}/status") @RequiresPermission("user:update") @RequiresMfaStepUp
    public Response status(@PathParam("id") String id, StatusRequest request) {
        if (request == null || request.enabled() == null) return bad("enabled is required");
        try { var updated = users.updateStatus(context(), id, request.enabled()); if (!request.enabled()) sessions.revokeAll(id); logs.record(context(), "UPDATE", "user-status", id, String.valueOf(request.enabled())); return Response.ok(ApiResponse.ok(updated)).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @Path("/{id}") @RequiresPermission("user:delete") @RequiresMfaStepUp @RejectApiKey
    public Response delete(@PathParam("id") String id) {
        try { users.delete(context(), id); logs.record(context(), "DELETE", "user", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @RequiresPermission("user:delete") @RequiresMfaStepUp @RejectApiKey
    public Response deleteBatch(@QueryParam("ids") String ids) {
        if (ids == null || ids.isBlank()) return bad("ids is required");
        try { var values = java.util.Arrays.stream(ids.split(",")).map(String::trim).map(app.keystone.identity.UuidValues::requireCanonical).toList(); int deleted = users.deleteAll(context(), values); logs.record(context(), "DELETE", "users", ids, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", deleted))).build(); }
        catch (IllegalArgumentException e) { return bad("ids must be comma separated UUIDs"); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    private String actor() { return identity.getPrincipal().getName(); }
    private AuthorizationContext context() { return authorization.context(identity); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(ErrorCode.VALIDATION_FAILED, message)).build(); }
    private static Response passwordRequired() { return Response.status(422).entity(ApiResponse.error(ErrorCode.PASSWORD_REQUIRED, "password does not meet security policy")).build(); }
    private static Response passwordPolicyError(PasswordPolicyException error) { return Response.status(422).entity(ApiResponse.error(error.errorCode(), error.getMessage())).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, "user not found")).build(); }
    public record UserRequest(String username, String password, String displayName, String deptId, String postId, String email, String phoneNumber, Integer sex, String avatar, String remark, Boolean enabled, Boolean clearDept, List<String> roleCodes) {
        public boolean clearDepartment() { return Boolean.TRUE.equals(clearDept); }
    }
    public record PasswordRequest(String password) {}
    public record StatusRequest(Boolean enabled) {}
    public record ImportResult(int total, int success, List<ImportFailure> failed) {}
    public record ImportFailure(int row, String username, String reason, String code) {}

    private static String importFailure(RuntimeException error) {
        if (error instanceof app.keystone.auth.AuthorizationDeniedException denied) return denied.code();
        if (error instanceof java.util.NoSuchElementException) return "record not found";
        if (error instanceof IllegalArgumentException argument && argument.getMessage() != null
                && !argument.getMessage().isBlank()) return argument.getMessage();
        return "user import failed";
    }

    private static String importFailureCode(RuntimeException error) {
        if (error instanceof UsernameAlreadyExistsException) return ErrorCode.USERNAME_ALREADY_EXISTS.code();
        if (error instanceof PasswordPolicyException policy) return policy.errorCode().code();
        if (error instanceof app.keystone.auth.AuthorizationDeniedException denied) return denied.code();
        if (error instanceof java.util.NoSuchElementException) return ErrorCode.RESOURCE_NOT_FOUND.code();
        if (error instanceof IllegalArgumentException) return ErrorCode.VALIDATION_FAILED.code();
        return ErrorCode.SERVICE_UNAVAILABLE.code();
    }
}
