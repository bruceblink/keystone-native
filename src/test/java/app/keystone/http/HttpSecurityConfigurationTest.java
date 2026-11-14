package app.keystone.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证启动配置拒绝空来源、通配符凭据和无代理范围的转发信任。 */
class HttpSecurityConfigurationTest {
    @Test
    void rejectsIncompleteCorsAndForwardedHttpsConfiguration() {
        var cors = configuration(true, "", true, false, false, "");
        assertThrows(IllegalStateException.class, () -> validate(cors));
        var wildcardCredentials = configuration(true, "*", true, false, false, "");
        assertThrows(IllegalStateException.class, () -> validate(wildcardCredentials));
        var forwardedWithoutProxy = configuration(false, "", false, true, true, "");
        assertThrows(IllegalStateException.class, () -> validate(forwardedWithoutProxy));
    }

    @Test
    void acceptsExplicitCorsAndTrustedProxyConfiguration() {
        var configuration = configuration(true, "https://admin.example.com", true, true, true, "10.0.0.0/8");
        assertDoesNotThrow(() -> validate(configuration));
    }

    private static HttpSecurityConfiguration configuration(boolean cors, String origins, boolean credentials,
                                                           boolean requireHttps, boolean trustForwarded, String trustedProxy) {
        var value = new HttpSecurityConfiguration();
        set(value, "corsEnabled", cors);
        set(value, "corsOrigins", origins);
        set(value, "corsCredentials", credentials);
        set(value, "requireHttps", requireHttps);
        set(value, "trustForwardedProto", trustForwarded);
        set(value, "trustedProxyCidrs", trustedProxy);
        return value;
    }

    private static void set(HttpSecurityConfiguration target, String field, Object value) {
        try {
            var declared = HttpSecurityConfiguration.class.getDeclaredField(field);
            declared.setAccessible(true);
            declared.set(target, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static void validate(HttpSecurityConfiguration target) {
        target.validate(null);
    }
}
