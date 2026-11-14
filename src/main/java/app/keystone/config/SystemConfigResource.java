package app.keystone.config;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/configs")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("config")
public class SystemConfigResource {
    @Inject SystemConfigRepository configs;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @RequiresPermission("config:read") public ApiResponse<List<SystemConfig>> list() { return ApiResponse.ok(configs.list(context())); }
    @GET @Path("/{key}") @RequiresPermission("config:read") public ApiResponse<SystemConfig> get(@PathParam("key") String key) { try { return ApiResponse.ok(configs.find(context(), key)); } catch (java.util.NoSuchElementException e) { throw new NotFoundException("config not found"); } }
    @POST @RequiresPermission("config:create") public Response create(ConfigRequest request) { if (request == null) return bad("request body is required"); try { var config = configs.create(context(), request.key(), request.value(), request.description()); logs.record(actor(), "CREATE", "config", String.valueOf(config.id()), config.key()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(config)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{key}") @RequiresPermission("config:update") public Response update(@PathParam("key") String key, ConfigRequest request) { if (request == null) return bad("request body is required"); try { var config = configs.update(context(), key, request.value(), request.description(), request.enabled()); logs.record(actor(), "UPDATE", "config", String.valueOf(config.id()), config.key()); return Response.ok(ApiResponse.ok(config)).build(); } catch (java.util.NoSuchElementException e) { return notFound(); } }
    @DELETE @Path("/{key}") @RequiresPermission("config:update") public Response delete(@PathParam("key") String key) { try { configs.delete(context(), key); logs.record(actor(), "DELETE", "config", key, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (java.util.NoSuchElementException e) { return notFound(); } }

    private AuthorizationContext context() { return authorization.context(identity); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("config not found")).build(); }
    public record ConfigRequest(String key, String value, String description, Boolean enabled) {}
}
