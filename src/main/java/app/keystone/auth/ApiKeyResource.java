package app.keystone.auth;

import app.keystone.ErrorCode;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;

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
        if (request == null || request.name() == null || request.name().isBlank()) return Response.status(422).entity(ApiResponse.error(ErrorCode.VALIDATION_FAILED, "name is required")).build();
        var user = users.findAuthUserByUsername(identity.getPrincipal().getName());
        if (user.isEmpty()) return Response.status(403).entity(ApiResponse.error(ErrorCode.PERMISSION_DENIED, "API key identity cannot issue API keys")).build();
        String userId = user.get().id();
        var value = keys.issue(userId, request.name(), request.scopes(), request.expiresAt());
        logs.record(identity.getPrincipal().getName(), "CREATE", "api-key", value.id(), value.prefix());
        return Response.status(201).entity(ApiResponse.ok(value)).build();
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
    public record Request(String name, List<String> scopes, Instant expiresAt) {}
}
