package app.keystone.auth;

import io.quarkus.runtime.Startup;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * 在应用启动时检查 JWT 必需配置，避免服务已接收请求但无法签发或验证令牌。
 * 私钥内容仍交给 SmallRye JWT 读取；本检查只验证位置可访问，不记录密钥内容。
 */
@Startup
@ApplicationScoped
public class JwtConfigurationStartupCheck {
    @ConfigProperty(name = "keystone.security.jwt.public-key-location", defaultValue = "")
    String publicKeyLocation;
    @ConfigProperty(name = "mp.jwt.verify.publickey.location", defaultValue = "")
    String verificationKeyLocation;
    @ConfigProperty(name = "smallrye.jwt.sign.key.location", defaultValue = "")
    String privateKeyLocation;
    @ConfigProperty(name = "keystone.security.jwt.key-id", defaultValue = "")
    String keyId;
    @ConfigProperty(name = "keystone.security.jwt.jwk-keys", defaultValue = "")
    String additionalJwkKeys;

    /** 启动前验证密钥标识和公私钥位置；失败会阻止应用进入可服务状态。 */
    void onStart(@Observes StartupEvent ignored) {
        AccessTokenService.requireKeyId(keyId);
        List<JwkSetService.KeySource> sources = JwkSetService.keySources(publicKeyLocation, keyId, additionalJwkKeys);
        for (JwkSetService.KeySource source : sources) {
            requireReadable("JWT public key " + source.keyId(), source.location());
        }
        requireOverlappingVerificationKey(verificationKeyLocation, publicKeyLocation, sources.size());
        requireReadable("JWT signing key", privateKeyLocation);
    }

    /**
     * SmallRye JWT 将 PEM 位置解析为单个固定公钥。配置重叠 key 时，必须显式使用 JWK Set
     * 文件或 HTTPS 地址，否则旧 key 虽然会出现在发现端点，实际验证仍然只接受当前 PEM。
     */
    static void requireOverlappingVerificationKey(String verificationLocation, String publishedLocation, int keyCount) {
        if (keyCount <= 1) return;
        if (verificationLocation == null || verificationLocation.isBlank()) {
            throw new IllegalStateException("JWT overlapping keys require a JWK Set verification location");
        }
        String verification = verificationLocation.trim();
        if (verification.equals(publishedLocation == null ? "" : publishedLocation.trim())) {
            throw new IllegalStateException("JWT overlapping keys cannot use the publishing PEM location for verification");
        }
        if (verification.startsWith("https://")) return;
        if (verification.startsWith("http://")) {
            throw new IllegalStateException("JWT overlapping keys require an HTTPS JWK Set URL");
        }
        try {
            String json = new String(readLocation(verification), StandardCharsets.UTF_8);
            if (!looksLikeJwkSet(json)) {
                throw new IllegalStateException("JWT overlapping keys require a JWK Set file");
            }
        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalStateException("JWT overlapping keys require a readable JWK Set file", e);
        }
    }

    private static boolean looksLikeJwkSet(String content) {
        String compact = content == null ? "" : content.replaceAll("\\s+", "");
        return compact.startsWith("{")
                && compact.contains("\"keys\":[")
                && compact.contains("\"kty\":\"RSA\"")
                && compact.contains("\"kid\":\"");
    }

    private static byte[] readLocation(String location) throws IOException {
        if (location.startsWith("classpath:")) return readResource(location.substring("classpath:".length()));
        if (location.startsWith("file:")) return Files.readAllBytes(Paths.get(URI.create(location)));
        Path path = Paths.get(location);
        if (Files.isRegularFile(path)) return Files.readAllBytes(path);
        return readResource(location);
    }

    private static byte[] readResource(String resourceName) throws IOException {
        String normalized = resourceName == null ? "" : resourceName.trim();
        while (normalized.startsWith("/")) normalized = normalized.substring(1);
        if (normalized.isBlank()) throw new IOException("JWT key resource is unavailable");
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        if (loader == null) loader = JwtConfigurationStartupCheck.class.getClassLoader();
        try (InputStream stream = loader.getResourceAsStream(normalized)) {
            if (stream == null) throw new IOException("JWT key resource is unavailable");
            return stream.readAllBytes();
        }
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
