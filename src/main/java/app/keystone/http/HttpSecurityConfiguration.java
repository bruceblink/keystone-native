package app.keystone.http;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** 在启动阶段校验 CORS、HTTPS 和代理信任配置，阻止不完整的生产安全配置。 */
@ApplicationScoped
public class HttpSecurityConfiguration {
    @ConfigProperty(name = "quarkus.http.cors.enabled", defaultValue = "false")
    boolean corsEnabled;

    @ConfigProperty(name = "keystone.security.http.cors-origins", defaultValue = "__unset__")
    String corsOrigins;

    @ConfigProperty(name = "quarkus.http.cors.access-control-allow-credentials", defaultValue = "false")
    boolean corsCredentials;

    @ConfigProperty(name = "keystone.security.http.require-https", defaultValue = "false")
    boolean requireHttps;

    @ConfigProperty(name = "keystone.security.http.trust-forwarded-proto", defaultValue = "false")
    boolean trustForwardedProto;

    @ConfigProperty(name = "keystone.security.network.trusted-proxy-cidrs", defaultValue = "")
    String trustedProxyCidrs;

    void validate(@Observes StartupEvent ignored) {
        String origins = corsOrigins == null ? "" : corsOrigins.trim();
        boolean originsConfigured = !origins.isBlank() && !"__unset__".equals(origins);
        if (corsEnabled && !originsConfigured) throw new IllegalStateException("HTTP_CORS_ORIGINS is required when CORS is enabled");
        if (corsCredentials && (!originsConfigured || origins.contains("*"))) {
            throw new IllegalStateException("CORS credentials require explicit non-wildcard origins");
        }
        if (requireHttps && trustForwardedProto && (trustedProxyCidrs == null || trustedProxyCidrs.isBlank())) {
            throw new IllegalStateException("trusted proxy CIDRs are required when forwarded HTTPS is trusted");
        }
    }
}
