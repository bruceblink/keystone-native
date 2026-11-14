package app.keystone.audit;

import app.keystone.ApiResponse;
import app.keystone.ExcelExporter;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import app.keystone.auth.RequiresPermission;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/** 登录日志导出入口；只输出非敏感审计字段。 */
@Path("/v1/login-logs")
@Produces(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("audit")
public class LoginLogResource {
    @Inject LoginLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @Path("/export") @Produces(ExcelExporter.CONTENT_TYPE) @RequiresPermission("login-log:export")
    public Response export(@QueryParam("username") String username, @QueryParam("status") String status) {
        byte[] workbook = LoginLogExcelExporter.export(logs.export(context(), username, status));
        return Response.ok(workbook).type(ExcelExporter.CONTENT_TYPE)
                .header("Content-Disposition", "attachment; filename=login-logs.xlsx")
                .build();
    }

    /** 删除指定登录日志；混合目标缺失时由仓储事务整体回滚。 */
    @jakarta.ws.rs.DELETE @RequiresPermission("login-log:delete")
    public Response delete(@QueryParam("ids") String ids) {
        if (ids == null || ids.isBlank()) return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("ids is required")).build();
        try {
            var values = java.util.Arrays.stream(ids.split(",")).map(String::trim).toList();
            values.forEach(app.keystone.identity.UuidValues::requireCanonical);
            return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", logs.delete(context(), values)))).build();
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("ids must be comma separated UUIDs")).build();
        } catch (java.util.NoSuchElementException e) {
            return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error(e.getMessage())).build();
        }
    }

    private AuthorizationContext context() {
        return authorization.context(identity);
    }
}
