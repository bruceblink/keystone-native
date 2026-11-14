package app.keystone.http;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.ConfigProvider;

/** 为 API 响应统一设置浏览器安全头和敏感数据缓存策略。 */
@Provider
@Priority(Priorities.HEADER_DECORATOR)
public class SecurityHeadersFilter implements ContainerResponseFilter {
    private static final String NO_STORE = "no-store, max-age=0";

    /** 测试可以设置此字段验证启用分支；生产请求始终读取当前运行时环境。 */
    Boolean hstsEnabled;

    /** 每次响应读取 HSTS 开关，避免 native image 固化构建阶段的生产配置。 */
    private boolean isHstsEnabled() {
        if (hstsEnabled != null) return hstsEnabled;
        String value = System.getenv("KEYSTONE_SECURITY_HTTP_HSTS");
        if (value == null) value = System.getenv("HTTP_HSTS_ENABLED");
        return value == null
                ? ConfigProvider.getConfig().getOptionalValue("keystone.security.http.hsts", Boolean.class).orElse(false)
                : Boolean.parseBoolean(value);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        responseContext.getHeaders().putSingle("X-Content-Type-Options", "nosniff");
        responseContext.getHeaders().putSingle("X-Frame-Options", "DENY");
        responseContext.getHeaders().putSingle("Referrer-Policy", "no-referrer");
        responseContext.getHeaders().putSingle("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
        responseContext.getHeaders().putSingle("Cross-Origin-Resource-Policy", "same-origin");
        if (isHstsEnabled()) responseContext.getHeaders().putSingle("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        if (isApiResponse(requestContext, responseContext)) responseContext.getHeaders().putSingle("Cache-Control", NO_STORE);
    }

    private static boolean isApiResponse(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        MediaType mediaType = responseContext.getMediaType();
        if (mediaType != null && MediaType.APPLICATION_JSON_TYPE.isCompatible(mediaType)) return true;
        String path = requestContext.getUriInfo().getPath();
        return path != null && (path.equals("v1") || path.startsWith("v1/"));
    }
}
