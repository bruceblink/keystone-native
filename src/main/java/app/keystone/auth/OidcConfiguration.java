package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.net.URI;

/** 集中保存 OIDC 依赖方配置，并在启用时拒绝不完整的生产配置。 */
@ApplicationScoped
public class OidcConfiguration {
    private static final String UNSET = "__unset__";
    @ConfigProperty(name = "keystone.security.oidc.enabled", defaultValue = "false") boolean enabled;
    @ConfigProperty(name = "keystone.security.oidc.issuer", defaultValue = UNSET) String issuer;
    @ConfigProperty(name = "keystone.security.oidc.authorization-endpoint", defaultValue = UNSET) String authorizationEndpoint;
    @ConfigProperty(name = "keystone.security.oidc.token-endpoint", defaultValue = UNSET) String tokenEndpoint;
    @ConfigProperty(name = "keystone.security.oidc.jwks-uri", defaultValue = UNSET) String jwksUri;
    @ConfigProperty(name = "keystone.security.oidc.client-id", defaultValue = UNSET) String clientId;
    @ConfigProperty(name = "keystone.security.oidc.client-secret", defaultValue = UNSET) String clientSecret;
    @ConfigProperty(name = "keystone.security.oidc.redirect-uri", defaultValue = UNSET) String redirectUri;
    @ConfigProperty(name = "keystone.security.oidc.audience", defaultValue = UNSET) String audience;
    @ConfigProperty(name = "keystone.security.oidc.request-ttl-seconds", defaultValue = "300") long requestTtlSeconds;
    @ConfigProperty(name = "keystone.security.oidc.http-timeout-seconds", defaultValue = "5") long httpTimeoutSeconds;

    public boolean enabled() { return enabled; }
    public String issuer() { return required(issuer, "OIDC issuer"); }
    public String authorizationEndpoint() { return httpsEndpoint(authorizationEndpoint, "OIDC authorization endpoint"); }
    public String tokenEndpoint() { return httpsEndpoint(tokenEndpoint, "OIDC token endpoint"); }
    public String jwksUri() { return httpsEndpoint(jwksUri, "OIDC JWKS URI"); }
    public String clientId() { return required(clientId, "OIDC client id"); }
    /** 公共客户端可以不配置密钥；机密客户端在令牌交换时发送该值。 */
    public String clientSecret() { return unset(clientSecret); }
    public String redirectUri() { return httpsEndpoint(redirectUri, "OIDC redirect URI"); }
    public String audience() { String value = unset(audience); return value.isBlank() ? clientId() : value; }
    public long requestTtlSeconds() { return bounded(requestTtlSeconds, 30, 900, "OIDC request TTL"); }
    public long httpTimeoutSeconds() { return bounded(httpTimeoutSeconds, 1, 30, "OIDC HTTP timeout"); }

    /** 启动检查在 OIDC 启用时调用，阻止缺失 provider 配置的半可用服务。 */
    public void validate() {
        if (enabled) {
            issuer(); authorizationEndpoint(); tokenEndpoint(); jwksUri(); clientId(); redirectUri();
            if (!isSecureOrLocal(issuer())) throw new IllegalStateException("OIDC issuer must use HTTPS or local HTTP");
        }
    }

    private static String required(String value, String name) {
        String normalized = unset(value);
        if (normalized.isBlank()) throw new IllegalStateException(name + " is not configured");
        return normalized;
    }

    private static String unset(String value) { return value == null || UNSET.equals(value) ? "" : value.trim(); }

    private static String httpsEndpoint(String value, String name) {
        String normalized = required(value, name);
        if (!isSecureOrLocal(normalized)) {
            throw new IllegalStateException(name + " must use HTTPS or local HTTP");
        }
        return normalized;
    }

    private static boolean isSecureOrLocal(String value) {
        try {
            URI uri = URI.create(value);
            if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null) return true;
            return "http".equalsIgnoreCase(uri.getScheme())
                    && ("localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static long bounded(long value, long min, long max, String name) {
        if (value < min || value > max) throw new IllegalStateException(name + " is out of range");
        return value;
    }
}
