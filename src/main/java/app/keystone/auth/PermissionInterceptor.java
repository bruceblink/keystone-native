package app.keystone.auth;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;

@RequiresPermission("")
@Interceptor
@Priority(Interceptor.Priority.APPLICATION + 100)
public class PermissionInterceptor {
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @AroundInvoke
    Object check(InvocationContext context) throws Exception {
        RequiresPermission requirement = context.getMethod().getAnnotation(RequiresPermission.class);
        if (requirement == null) requirement = context.getTarget().getClass().getAnnotation(RequiresPermission.class);
        if (identity == null || identity.isAnonymous()) throw new NotAuthorizedException("authentication is required");
        if (requirement == null || !authorization.allowed(identity, requirement.value())) throw new ForbiddenException("permission denied");
        return context.proceed();
    }
}
