package app.keystone.http;

import app.keystone.ApiResponse;
import app.keystone.auth.ClientAddressResolver;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.ConfigProvider;

/** 在生产入口强制使用 HTTPS，并只接受受信代理转发的 HTTPS 标识。 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class HttpsRequestFilter implements ContainerRequestFilter {
    @Inject
    ClientAddressResolver clientAddresses;

    @Context
    RoutingContext routingContext;

    /**
     * 每次请求读取入口开关，避免 native image 在构建阶段初始化 CDI 过滤器时固化环境变量。
     * 环境变量优先于 MicroProfile 配置，便于同一个镜像在不同部署环境使用不同入口策略。
     */
    private static boolean runtimeBoolean(String property, String... environmentNames) {
        for (String environmentName : environmentNames) {
            String value = System.getenv(environmentName);
            if (value != null) return Boolean.parseBoolean(value);
        }
        return ConfigProvider.getConfig().getOptionalValue(property, Boolean.class).orElse(false);
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (!runtimeBoolean(
                        "keystone.security.http.require-https",
                        "KEYSTONE_SECURITY_HTTP_REQUIRE_HTTPS",
                        "HTTP_REQUIRE_HTTPS")
                || isHttps(requestContext)) return;
        throw new WebApplicationException(Response.status(426)
                .type(MediaType.APPLICATION_JSON)
                .entity(ApiResponse.error("HTTPS is required"))
                .build());
    }

    private boolean isHttps(ContainerRequestContext requestContext) {
        String scheme = requestContext.getUriInfo().getRequestUri().getScheme();
        if ("https".equalsIgnoreCase(scheme)) return true;
        if (!runtimeBoolean(
                        "keystone.security.http.trust-forwarded-proto",
                        "KEYSTONE_SECURITY_HTTP_TRUST_FORWARDED_PROTO",
                        "HTTP_TRUST_FORWARDED_PROTO")
                || !clientAddresses.isTrustedProxy(remoteAddress())) return false;
        String forwarded = requestContext.getHeaderString("X-Forwarded-Proto");
        if (forwarded == null || forwarded.isBlank()) return false;
        return "https".equalsIgnoreCase(forwarded.split(",", -1)[0].trim());
    }

    private String remoteAddress() {
        if (routingContext == null || routingContext.request() == null || routingContext.request().remoteAddress() == null) {
            return null;
        }
        return routingContext.request().remoteAddress().host();
    }
}
