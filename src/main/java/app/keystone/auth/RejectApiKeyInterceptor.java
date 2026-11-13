package app.keystone.auth;

import app.keystone.ApiResponse;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.ForbiddenException;

/** 在业务方法执行前拒绝 API Key，避免机器凭据复用人类用户密码或主体管理能力。 */
@RejectApiKey
@Interceptor
@Priority(Interceptor.Priority.APPLICATION + 90)
public class RejectApiKeyInterceptor {
    @Inject SecurityIdentity identity;

    @AroundInvoke
    Object check(InvocationContext context) throws Exception {
        if (identity != null && !identity.isAnonymous() && "API_KEY".equals(identity.getAttribute("credentialType"))) {
            throw new ForbiddenException(ApiResponse.response(jakarta.ws.rs.core.Response.Status.FORBIDDEN.getStatusCode(), "permission_denied", "human credential is required"));
        }
        return context.proceed();
    }
}
