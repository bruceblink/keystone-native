package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.annotation.PostConstruct;
import io.quarkus.runtime.Startup;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** 控制 Passkey 功能是否开放，并检查启用时必须存在的可信 WebAuthn 参数。 */
@ApplicationScoped
@Startup
public class WebAuthnConfiguration {
    @ConfigProperty(name = "keystone.security.webauthn.enabled", defaultValue = "false")
    boolean enabled;
    @ConfigProperty(name = "keystone.security.webauthn.rp-id", defaultValue = "")
    String rpId;
    @ConfigProperty(name = "keystone.security.webauthn.origin", defaultValue = "")
    String origin;
    @ConfigProperty(name = "quarkus.http.auth.session.encryption-key", defaultValue = "")
    String sessionEncryptionKey;

    public boolean enabled() {
        return enabled;
    }

    @PostConstruct
    void validateAtStartup() {
        if (enabled) validate();
    }

    public String rpId() {
        return required(rpId, "WebAuthn relying party id");
    }

    public String origin() {
        return required(origin, "WebAuthn origin");
    }

    public void validate() {
        if (!enabled) return;
        String configuredOrigin = origin();
        if (!configuredOrigin.startsWith("https://") && !configuredOrigin.startsWith("http://localhost")) {
            throw new IllegalStateException("WebAuthn origin must use HTTPS or localhost");
        }
        rpId();
        if (sessionEncryptionKey == null || sessionEncryptionKey.length() < 32 || "__disabled__".equals(sessionEncryptionKey)) {
            throw new IllegalStateException("WebAuthn session encryption key is not configured");
        }
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalStateException(name + " is not configured");
        return value.trim();
    }
}
