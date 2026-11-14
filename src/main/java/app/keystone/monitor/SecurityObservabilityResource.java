package app.keystone.monitor;

import app.keystone.ApiResponse;
import app.keystone.audit.SecurityObservability;
import app.keystone.auth.RequiresPermission;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/** 为具备审计读取权限的运维人员提供认证异常和清理指标。 */
@Path("/v1/monitor/security")
@Produces(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("audit")
public class SecurityObservabilityResource {
    @Inject SecurityObservability observability;
    @Inject SecurityOperationsReport reports;

    @GET
    @RequiresPermission("audit:read")
    public ApiResponse<SecurityObservability.Metrics> metrics() {
        return ApiResponse.ok(observability.snapshot());
    }

    /** 返回按当前单租户和可选主体筛选的脱敏安全运营报告。 */
    @GET
    @Path("/report")
    @RequiresPermission("audit:read")
    public Response report(@QueryParam("subjectId") String subjectId,
                           @QueryParam("actor") String actor,
                           @QueryParam("credentialType") String credentialType,
                           @QueryParam("credentialId") String credentialId,
                           @QueryParam("from") String from,
                           @QueryParam("to") String to,
                           @QueryParam("page") Integer page,
                           @QueryParam("size") Integer size,
                           @QueryParam("horizonDays") Integer horizonDays) {
        try {
            return Response.ok(ApiResponse.ok(reports.generate(subjectId, actor, credentialType, credentialId,
                    from, to, page, size, horizonDays))).build();
        } catch (IllegalArgumentException e) {
            return Response.status(422)
                    .entity(ApiResponse.error("validation_failed", e.getMessage())).build();
        }
    }
}
