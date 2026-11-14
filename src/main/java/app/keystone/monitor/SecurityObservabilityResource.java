package app.keystone.monitor;

import app.keystone.ApiResponse;
import app.keystone.audit.SecurityObservability;
import app.keystone.auth.RequiresPermission;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/** 为具备审计读取权限的运维人员提供认证异常和清理指标。 */
@Path("/v1/monitor/security")
@Produces(MediaType.APPLICATION_JSON)
public class SecurityObservabilityResource {
    @Inject SecurityObservability observability;

    @GET
    @RequiresPermission("audit:read")
    public ApiResponse<SecurityObservability.Metrics> metrics() {
        return ApiResponse.ok(observability.snapshot());
    }
}
