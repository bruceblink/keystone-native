package app.keystone.audit;

import app.keystone.ApiResponse;
import app.keystone.auth.RequiresPermission;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Path("/logs")
@Produces(MediaType.APPLICATION_JSON)
public class LogCompatibilityResource {
    @Inject LoginLogRepository loginLogs;
    @Inject OperationLogRepository operationLogs;
    @Inject SecurityIdentity identity;

    @GET @Path("/loginLogs") @RequiresPermission("audit:read")
    public ApiResponse<LoginLogRepository.Page> loginLogs(@QueryParam("page") Integer page, @QueryParam("size") Integer size, @QueryParam("username") String username, @QueryParam("status") String status) { return ApiResponse.ok(loginLogs.list(page == null ? 1 : page, size == null ? 20 : size, username, status)); }

    @GET @Path("/loginLogs/excel") @RequiresPermission("audit:read")
    public Response loginLogsExport(@QueryParam("username") String username, @QueryParam("status") String status) { var page = loginLogs.list(1, 100, username, status); var rows = new java.util.ArrayList<String[]>(); rows.add(new String[]{"id", "username", "status", "ipAddress", "message", "loginAt"}); for (LoginLog log : page.items()) rows.add(new String[]{String.valueOf(log.id()), log.username(), log.status(), log.ipAddress(), log.message(), String.valueOf(log.loginAt())}); return app.keystone.compat.CsvExport.response("login-logs.csv", rows); }

    @DELETE @Path("/loginLogs") @RequiresPermission("audit:write")
    public Response deleteLoginLogs(@QueryParam("ids") String ids) { try { return Response.ok(ApiResponse.ok(Map.of("deleted", loginLogs.delete(parseIds(ids))))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }

    @GET @Path("/operationLogs") @RequiresPermission("audit:read")
    public ApiResponse<OperationLogRepository.Page> operationLogs(@QueryParam("page") Integer page, @QueryParam("size") Integer size, @QueryParam("actor") String actor, @QueryParam("action") String action, @QueryParam("resource") String resource) { return ApiResponse.ok(operationLogs.list(page == null ? 1 : page, size == null ? 20 : size, actor, action, resource)); }

    @GET @Path("/operationLogs/excel") @RequiresPermission("audit:read")
    public Response operationLogsExport(@QueryParam("actor") String actor, @QueryParam("action") String action, @QueryParam("resource") String resource) { var page = operationLogs.list(1, 100, actor, action, resource); var rows = new java.util.ArrayList<String[]>(); rows.add(new String[]{"id", "actor", "action", "resource", "resourceId", "detail", "createdAt"}); for (OperationLog log : page.items()) rows.add(new String[]{String.valueOf(log.id()), log.actorUsername(), log.action(), log.resource(), log.resourceId(), log.detail(), String.valueOf(log.createdAt())}); return app.keystone.compat.CsvExport.response("operation-logs.csv", rows); }

    @POST @Path("/operationLogs") @RequiresPermission("audit:write") @Consumes(MediaType.APPLICATION_JSON)
    public Response addOperationLog(OperationLogRequest request) { if (request == null || request.action() == null || request.resource() == null) return bad("action and resource are required"); operationLogs.record(identity.getPrincipal().getName(), request.action(), request.resource(), request.resourceId(), request.detail()); return Response.ok(ApiResponse.ok(Map.of("recorded", true))).build(); }

    @DELETE @Path("/operationLogs") @RequiresPermission("audit:write")
    public Response deleteOperationLogs(@QueryParam("ids") String ids) { try { return Response.ok(ApiResponse.ok(Map.of("deleted", operationLogs.delete(parseIds(ids))))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }

    private static List<Long> parseIds(String ids) { if (ids == null || ids.isBlank()) throw new IllegalArgumentException("ids is required"); try { return Arrays.stream(ids.split(",")).map(String::trim).map(Long::valueOf).toList(); } catch (NumberFormatException e) { throw new IllegalArgumentException("ids must be comma separated numbers"); } }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    public record OperationLogRequest(String action, String resource, String resourceId, String detail) {}
}
