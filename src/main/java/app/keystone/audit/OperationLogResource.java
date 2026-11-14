package app.keystone.audit;

import app.keystone.ApiResponse;
import app.keystone.auth.RequiresPermission;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

@Path("/v1/operation-logs")
@Produces(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("audit")
public class OperationLogResource {
    @Inject OperationLogRepository logs;

    @GET @RequiresPermission("audit:read")
    public ApiResponse<OperationLogRepository.Page> list(@QueryParam("page") Integer page, @QueryParam("size") Integer size, @QueryParam("actor") String actor, @QueryParam("action") String action, @QueryParam("resource") String resource) { return ApiResponse.ok(logs.list(page == null ? 1 : page, size == null ? 20 : size, actor, action, resource)); }

    @jakarta.ws.rs.DELETE @RequiresPermission("operation-log:delete")
    public ApiResponse<java.util.Map<String, Integer>> delete(@QueryParam("ids") String ids) {
        if (ids == null || ids.isBlank()) throw new jakarta.ws.rs.BadRequestException("ids is required");
        try { var values = java.util.Arrays.stream(ids.split(",")).map(String::trim).toList(); values.forEach(app.keystone.identity.UuidValues::requireCanonical); return ApiResponse.ok(java.util.Map.of("deleted", logs.delete(values))); }
        catch (IllegalArgumentException e) { throw new jakarta.ws.rs.BadRequestException("ids must be comma separated UUIDs"); }
    }
}
