package app.keystone.auth;

import app.keystone.ErrorCode;
import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.user.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.NoSuchElementException;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Path("/v1/api-keys")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RequiresDataScope("api-key")
public class ApiKeyResource {
    @Inject ApiKeyRepository keys;
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @POST @RequiresPermission("api-key:create") @RequiresMfaStepUp public Response issue(Request request) {
        if (request == null) return Response.status(422).entity(ApiResponse.error(ErrorCode.VALIDATION_FAILED, "request is invalid")).build();
        Instant expiresAt;
        try {
            expiresAt = parseExpiry(request.expiresAt());
        } catch (DateTimeParseException | IllegalArgumentException e) {
            return Response.status(422).entity(ApiResponse.error(ErrorCode.API_KEY_EXPIRY_INVALID,
                    "API Key expiration must be a valid ISO-8601 date-time")).build();
        }
        var user = users.findAuthUserByUsername(identity.getPrincipal().getName());
        if (user.isEmpty()) return Response.status(403).entity(ApiResponse.error(ErrorCode.PERMISSION_DENIED, "API key identity cannot issue API keys")).build();
        String userId = user.get().id();
        ApiKeyRepository.IssuedApiKey value;
        try {
            value = keys.issue(userId, request.name(), request.scopes(), expiresAt);
        } catch (ApiKeyIssueValidationException e) {
            return Response.status(422).entity(ApiResponse.error(e.errorCode(), e.getMessage())).build();
        }
        logs.record(identity.getPrincipal().getName(), "CREATE", "api-key", value.id(), value.prefix());
        return Response.status(201).entity(ApiResponse.ok(value)).build();
    }
    /** 只在 API Key 签发边界解析日期，避免影响其他请求 DTO 的 JSON 日期错误映射。 */
    private static Instant parseExpiry(JsonNode value) {
        if (value == null || value.isNull()) return null;
        if (!value.isTextual()) throw new IllegalArgumentException("expiresAt must be a string");
        return Instant.parse(value.textValue());
    }
    /** page/size 传入时返回分页对象；省略时保留旧数组响应，兼容旧调用方。 */
    @GET @RequiresPermission("api-key:read") public Response list(
            @QueryParam("page") Integer page,
            @QueryParam("size") Integer size,
            @QueryParam("keyword") String keyword,
            @QueryParam("status") String status) {
        var user = owner();
        if (page == null && size == null) return Response.ok(ApiResponse.ok(keys.list(user.id()))).build();
        return Response.ok(ApiResponse.ok(keys.list(user.id(), page == null ? 1 : page,
                size == null ? 20 : size, keyword, status))).build();
    }
    @POST @Path("/{id}/rotate") @RequiresPermission("api-key:rotate") @RequiresMfaStepUp public Response rotate(@PathParam("id") String id) {
        var user = owner();
        try { var value = keys.rotate(user.id(), id); logs.record(identity.getPrincipal().getName(), "ROTATE", "api-key", id, value.prefix()); return Response.ok(ApiResponse.ok(value)).build(); }
        catch (ApiKeyRepository.ApiKeyExpiredException e) { return Response.status(409).entity(ApiResponse.error(ErrorCode.API_KEY_EXPIRED, e.getMessage())).build(); }
        catch (ApiKeyRepository.ApiKeyScopeUnavailableException e) { return Response.status(422).entity(ApiResponse.error(ErrorCode.API_KEY_SCOPE_UNAVAILABLE, e.getMessage())).build(); }
        catch (NoSuchElementException e) { return Response.status(404).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, e.getMessage())).build(); }
        catch (IllegalArgumentException e) { return Response.status(409).entity(ApiResponse.error(ErrorCode.RESOURCE_CONFLICT, e.getMessage())).build(); }
    }
    @DELETE @Path("/{id}") @RequiresPermission("api-key:revoke") @RequiresMfaStepUp public Response revoke(@PathParam("id") String id) {
        var user = owner();
        try { keys.revoke(user.id(), id); logs.record(identity.getPrincipal().getName(), "REVOKE", "api-key", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("revoked", true))).build(); }
        catch (NoSuchElementException e) { return Response.status(404).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, e.getMessage())).build(); }
    }
    private UserRepository.AuthUser owner() {
        var user = users.findAuthUserByUsername(identity.getPrincipal().getName());
        if (user.isEmpty() || "API_KEY".equals(identity.getAttribute("credentialType"))) {
            throw new ForbiddenException(ApiResponse.response(Response.Status.FORBIDDEN.getStatusCode(), ErrorCode.PERMISSION_DENIED, "API key identity cannot manage API keys"));
        }
        return user.get();
    }
    public record Request(String name, List<String> scopes,
                          @Schema(type = SchemaType.STRING, format = "date-time") JsonNode expiresAt) {}
}
