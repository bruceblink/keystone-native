package app.keystone.auth;

import io.quarkus.runtime.Startup;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 在应用启动时检查 JWT 必需配置，避免服务已接收请求但无法签发或验证令牌。
 * 私钥内容仍交给 SmallRye JWT 读取；本检查只验证位置可访问，不记录密钥内容。
 */
@Startup
@ApplicationScoped
public class JwtConfigurationStartupCheck {
    @ConfigProperty(name = "mp.jwt.verify.publickey.location", defaultValue = "")
    String publicKeyLocation;
    @ConfigProperty(name = "smallrye.jwt.sign.key.location", defaultValue = "")
    String privateKeyLocation;
    @ConfigProperty(name = "keystone.security.jwt.key-id", defaultValue = "")
    String keyId;

    /** 启动前验证密钥标识和公私钥位置；失败会阻止应用进入可服务状态。 */
    void onStart(@Observes StartupEvent ignored) {
        AccessTokenService.requireKeyId(keyId);
        requireReadable("JWT public key", publicKeyLocation);
        requireReadable("JWT signing key", privateKeyLocation);
    }

    static void requireReadable(String name, String location) {
        if (location == null || location.isBlank()) throw new IllegalStateException(name + " location is not configured");
        try {
            if (location.startsWith("classpath:")) {
                requireResource(name, location.substring("classpath:".length()));
                return;
            }
            if (location.startsWith("file:")) {
                requireFile(name, Paths.get(URI.create(location)));
                return;
            }
            Path path = Paths.get(location);
            if (Files.isRegularFile(path)) return;
            requireResource(name, location);
        } catch (IllegalArgumentException | IOException e) {
            throw new IllegalStateException(name + " location is not readable", e);
        }
    }

    private static void requireFile(String name, Path path) throws IOException {
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) throw new IOException(name + " file is unavailable");
    }

    private static void requireResource(String name, String resourceName) throws IOException {
        String normalized = resourceName == null ? "" : resourceName.trim();
        while (normalized.startsWith("/")) normalized = normalized.substring(1);
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        if (loader == null) loader = JwtConfigurationStartupCheck.class.getClassLoader();
        try (InputStream stream = loader.getResourceAsStream(normalized)) {
            if (stream == null) throw new IOException(name + " resource is unavailable");
        }
    }
}
