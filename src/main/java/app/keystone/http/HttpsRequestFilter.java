package app.keystone.http;

import app.keystone.ApiResponse;
import app.keystone.auth.ClientAddressResolver;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.PostConstruct;
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
    boolean requireHttps;

    boolean trustForwardedProto;

    @Inject
    ClientAddressResolver clientAddresses;

    @Context
    RoutingContext routingContext;

    /** 在运行时读取安全开关，允许同一个 native 镜像按部署环境切换入口策略。 */
    @PostConstruct
    void loadRuntimeConfiguration() {
        var config = ConfigProvider.getConfig();
        requireHttps = runtimeBoolean(config, "keystone.security.http.require-https", "KEYSTONE_SECURITY_HTTP_REQUIRE_HTTPS", "HTTP_REQUIRE_HTTPS");
        trustForwardedProto = runtimeBoolean(config, "keystone.security.http.trust-forwarded-proto", "KEYSTONE_SECURITY_HTTP_TRUST_FORWARDED_PROTO", "HTTP_TRUST_FORWARDED_PROTO");
    }

    private static boolean runtimeBoolean(org.eclipse.microprofile.config.Config config, String property, String... environmentNames) {
        for (String environmentName : environmentNames) {
            String value = System.getenv(environmentName);
            if (value != null) return Boolean.parseBoolean(value);
        }
        return config.getOptionalValue(property, Boolean.class).orElse(false);
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (!requireHttps || isHttps(requestContext)) return;
        throw new WebApplicationException(Response.status(426)
                .type(MediaType.APPLICATION_JSON)
                .entity(ApiResponse.error("HTTPS is required"))
                .build());
    }

    private boolean isHttps(ContainerRequestContext requestContext) {
        String scheme = requestContext.getUriInfo().getRequestUri().getScheme();
        if ("https".equalsIgnoreCase(scheme)) return true;
        if (!trustForwardedProto || !clientAddresses.isTrustedProxy(remoteAddress())) return false;
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
