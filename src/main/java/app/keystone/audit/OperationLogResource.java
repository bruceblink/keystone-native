package app.keystone.audit;

import app.keystone.ApiResponse;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

@Path("/v1/operation-logs")
@Produces(MediaType.APPLICATION_JSON)
@RolesAllowed("ADMIN")
public class OperationLogResource {
    @Inject OperationLogRepository logs;

    @GET
    public ApiResponse<OperationLogRepository.Page> list(@QueryParam("page") Integer page, @QueryParam("size") Integer size) { return ApiResponse.ok(logs.list(page == null ? 1 : page, size == null ? 20 : size)); }
}
