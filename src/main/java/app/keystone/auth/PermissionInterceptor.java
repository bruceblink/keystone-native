package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.ErrorCode;
import app.keystone.audit.SecurityEventRepository;
import app.keystone.audit.SecurityEventContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.ws.rs.core.Context;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.core.Response;

@RequiresPermission("")
@Interceptor
@Priority(Interceptor.Priority.APPLICATION + 100)
public class PermissionInterceptor {
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;
    @Inject SecurityEventRepository securityEvents;
    @Inject ClientAddressResolver clientAddresses;
    @Context RoutingContext routingContext;

    @AroundInvoke
    Object check(InvocationContext context) throws Exception {
        RequiresPermission requirement = context.getMethod().getAnnotation(RequiresPermission.class);
        if (requirement == null) requirement = context.getTarget().getClass().getAnnotation(RequiresPermission.class);
        if (identity == null || identity.isAnonymous()) throw new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), ErrorCode.AUTHENTICATION_REQUIRED, "authentication is required"));
        String[] requiredPermissions = requiredPermissions(requirement);
        if (requiredPermissions.length == 0 || java.util.Arrays.stream(requiredPermissions).noneMatch(PermissionCatalog::contains)) throw new ForbiddenException(ApiResponse.response(Response.Status.FORBIDDEN.getStatusCode(), ErrorCode.PERMISSION_DENIED, "permission denied"));
        try {
            if (java.util.Arrays.stream(requiredPermissions).noneMatch(permission -> authorization.allowed(identity, permission))) {
                recordDenied(String.join("|", requiredPermissions), "permission denied");
                throw new ForbiddenException(ApiResponse.response(Response.Status.FORBIDDEN.getStatusCode(), ErrorCode.PERMISSION_DENIED, "permission denied"));
            }
        } catch (IllegalStateException e) {
            recordDenied(String.join("|", requiredPermissions), "authorization state is unavailable");
            throw new ServiceUnavailableException(ApiResponse.response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), ErrorCode.AUTHORIZATION_UNAVAILABLE, "authorization state is unavailable"), e);
        }
        return context.proceed();
    }

    /** 将单权限和任一权限声明统一成拦截器内部使用的候选集合。 */
    private static String[] requiredPermissions(RequiresPermission requirement) {
        if (requirement == null) return new String[0];
        return requirement.any().length > 0 ? requirement.any() : new String[]{requirement.value()};
    }

    private void recordDenied(String permission, String detail) {
        try {
            String actor = identity == null || identity.isAnonymous() ? null : identity.getPrincipal().getName();
            Object credentialValue = identity == null || identity.isAnonymous() ? null : identity.getAttribute("credentialType");
            String credential = credentialValue == null ? null : String.valueOf(credentialValue);
            Object credentialIdValue = identity == null || identity.isAnonymous() ? null : identity.getAttribute("credentialId");
            String credentialId = credentialIdValue == null ? null : String.valueOf(credentialIdValue);
            String forwardedFor = routingContext == null || routingContext.request() == null ? null : routingContext.request().getHeader("X-Forwarded-For");
            String sourceIp = clientAddresses.resolve(routingContext, forwardedFor);
            securityEvents.record("AUTHORIZATION", actor, credential, credentialId, sourceIp, "permission", permission, "DENIED",
                    SecurityEventContext.from(identity, routingContext), detail);
        } catch (IllegalStateException ignored) { }
    }
}
