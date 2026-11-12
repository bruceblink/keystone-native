package app.keystone.auth;

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
public class ApiKeyResource {
    @Inject ApiKeyRepository keys;
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @POST @RequiresPermission("api-key:create") public Response issue(Request request) {
        if (request == null || request.name() == null || request.name().isBlank()) return Response.status(400).entity(ApiResponse.error("name is required")).build();
        var user = users.findAuthUserByUsername(identity.getPrincipal().getName());
        if (user.isEmpty()) return Response.status(403).entity(ApiResponse.error("API key identity cannot issue API keys")).build();
        long userId = user.get().id();
        var value = keys.issue(userId, request.name(), request.scopes(), request.expiresAt());
        logs.record(identity.getPrincipal().getName(), "CREATE", "api-key", value.id(), value.prefix());
        return Response.status(201).entity(ApiResponse.ok(value)).build();
    }
    @GET @RequiresPermission("api-key:read") public Response list() {
        var user = owner();
        return Response.ok(ApiResponse.ok(keys.list(user.id()))).build();
    }
    @POST @Path("/{id}/rotate") @RequiresPermission("api-key:rotate") public Response rotate(@PathParam("id") String id) {
        var user = owner();
        try { var value = keys.rotate(user.id(), id); logs.record(identity.getPrincipal().getName(), "ROTATE", "api-key", id, value.prefix()); return Response.ok(ApiResponse.ok(value)).build(); }
        catch (NoSuchElementException e) { return Response.status(404).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalArgumentException e) { return Response.status(409).entity(ApiResponse.error(e.getMessage())).build(); }
    }
    @DELETE @Path("/{id}") @RequiresPermission("api-key:revoke") public Response revoke(@PathParam("id") String id) {
        var user = owner();
        try { keys.revoke(user.id(), id); logs.record(identity.getPrincipal().getName(), "REVOKE", "api-key", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("revoked", true))).build(); }
        catch (NoSuchElementException e) { return Response.status(404).entity(ApiResponse.error(e.getMessage())).build(); }
    }
    private UserRepository.AuthUser owner() {
        var user = users.findAuthUserByUsername(identity.getPrincipal().getName());
        if (user.isEmpty() || "API_KEY".equals(identity.getAttribute("credentialType"))) throw new NotAuthorizedException("API key identity cannot manage API keys");
        return user.get();
    }
    public record Request(String name, List<String> scopes, Instant expiresAt) {}
}
