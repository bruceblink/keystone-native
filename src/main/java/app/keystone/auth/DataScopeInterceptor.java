package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.core.Response;

/**
 * 在资源入口执行公共数据范围矩阵。
 *
 * <p>用户和部门资源由仓储查询条件继续细分；公告和任务使用 OWNER 关系过滤，其他没有稳定
 * owner/member 关系的资源要求 ALL 或 TENANT，避免普通部门角色通过列表、详情或写入口访问全局数据。</p>
 */
@RequiresDataScope("")
@Interceptor
@Priority(Interceptor.Priority.APPLICATION + 110)
public class DataScopeInterceptor {
    @Inject SecurityIdentity identity;
    @Inject ApiKeyUserRepository users;
    @Inject DataScopeService dataScopes;

    @AroundInvoke
    Object check(InvocationContext context) throws Exception {
        RequiresDataScope requirement = requirement(context);
        if (requirement == null) return context.proceed();
        if (identity == null || identity.isAnonymous()) {
            throw new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "authentication is required"));
        }
        try {
            String subjectId = subjectId();
            DataScopeService.Scope scope = dataScopes.forUser(subjectId);
            DataScopePolicy.ResourceRule rule = DataScopePolicy.rule(requirement.value());
            if (!DataScopePolicy.allows(rule, scope.all(), scope.self(), scope.owner())) {
                throw new ForbiddenException(ApiResponse.response(Response.Status.FORBIDDEN.getStatusCode(), "data_scope_denied", "data scope does not allow this resource"));
            }
            return context.proceed();
        } catch (NotAuthorizedException | ForbiddenException e) {
            throw e;
        } catch (IllegalStateException e) {
            throw new ServiceUnavailableException(ApiResponse.response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), "authorization_unavailable", "data scope is unavailable"), e);
        }
    }

    private String subjectId() {
        Object attribute = identity.getAttribute("userId");
        if (attribute instanceof String value && !value.isBlank()) {
            return app.keystone.identity.UuidValues.requireCanonical(value);
        }
        return users.findAuthUserByUsername(identity.getPrincipal().getName())
                .orElseThrow(() -> new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "subject is unavailable")))
                .id();
    }

    /** 读取方法声明类上的范围注解；CDI 代理类本身通常不保留业务类注解。 */
    private static RequiresDataScope requirement(InvocationContext context) {
        RequiresDataScope requirement = context.getMethod().getAnnotation(RequiresDataScope.class);
        if (requirement != null) return requirement;
        Class<?> declaringClass = context.getMethod().getDeclaringClass();
        requirement = declaringClass.getAnnotation(RequiresDataScope.class);
        if (requirement != null) return requirement;
        for (Class<?> targetClass = context.getTarget().getClass(); targetClass != null; targetClass = targetClass.getSuperclass()) {
            requirement = targetClass.getAnnotation(RequiresDataScope.class);
            if (requirement != null) return requirement;
        }
        return null;
    }
}
