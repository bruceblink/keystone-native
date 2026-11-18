package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.ErrorCode;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;

/** 为已登录的人类会话返回当前有效权限和资源列表范围。 */
@Path("/v1/auth/me")
@jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
public class AuthCapabilitiesResource {
    private static final Logger LOG = Logger.getLogger(AuthCapabilitiesResource.class);
    private static final List<String> RESOURCE_NAMES = List.of(
            "user", "department", "profile", "role", "post", "menu", "config", "dictionary",
            "notice", "job", "audit", "session", "api-key");

    @Inject AuthorizationService authorization;
    @Inject SecurityIdentity identity;

    /** 按本次请求重新计算授权，不缓存结果，也不要求管理权限。 */
    @GET
    @Path("/capabilities")
    @RejectApiKey
    public Response capabilities() {
        if (identity == null || identity.isAnonymous()) {
            return ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(),
                    ErrorCode.AUTHENTICATION_REQUIRED, "authentication is required");
        }
        try {
            AuthorizationContext context = authorization.context(identity);
            List<String> permissions = PermissionCatalog.values().stream()
                    .filter(context::hasPermission)
                    .sorted()
                    .toList();
            Map<String, Boolean> resources = resourceScopes(context);
            return Response.ok(ApiResponse.ok(new Capabilities(permissions, resources))).build();
        } catch (AuthorizationDeniedException denied) {
            return ApiResponse.response(denied.status(), ErrorCode.fromCode(denied.code()), denied.getMessage());
        } catch (RuntimeException unavailable) {
            LOG.warnf("Capabilities authorization unavailable (%s)", unavailable.getClass().getSimpleName());
            return ApiResponse.response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(),
                    ErrorCode.AUTHORIZATION_UNAVAILABLE, "authorization state is unavailable");
        }
    }

    /** 范围布尔值只说明列表入口可执行；查询结果仍由各资源仓储按范围过滤。 */
    private static Map<String, Boolean> resourceScopes(AuthorizationContext context) {
        Map<String, Boolean> resources = new LinkedHashMap<>();
        for (String resource : RESOURCE_NAMES) {
            resources.put(resource, DataScopePolicy.allows(DataScopePolicy.rule(resource),
                    context.allScope(), context.selfScope(), context.ownerScope()));
        }
        return Collections.unmodifiableMap(resources);
    }

    public record Capabilities(List<String> permissions, Map<String, Boolean> resources) { }
}
