package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 从外部 RSA 公钥生成 RFC 7517 JWK Set。
 *
 * <p>服务只读取验证公钥，不读取签名私钥。当前只发布配置中的一个 key；密钥重叠和
 * 多 key 发布需要后续接入 key registry 后再实现。</p>
 */
@ApplicationScoped
public class JwkSetService {
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    private static final long DEFAULT_CACHE_SECONDS = 60;
    private final String publicKeyLocation;
    private final String keyId;
    private final long cacheTtlNanos;
    private volatile CachedKey cached;

    @Inject
    public JwkSetService(
            @ConfigProperty(name = "mp.jwt.verify.publickey.location", defaultValue = "") String publicKeyLocation,
            @ConfigProperty(name = "keystone.security.jwt.key-id", defaultValue = "") String keyId,
            @ConfigProperty(name = "keystone.security.jwt.jwk-cache-seconds", defaultValue = "60") long cacheSeconds) {
        this.publicKeyLocation = publicKeyLocation == null ? "" : publicKeyLocation.trim();
        this.keyId = AccessTokenService.requireKeyId(keyId);
        this.cacheTtlNanos = cacheTtlNanos(cacheSeconds);
    }

    /** 测试和嵌入式调用使用固定缓存时长，生产实例由配置构造。 */
    public JwkSetService(String publicKeyLocation, String keyId) {
        this(publicKeyLocation, keyId, DEFAULT_CACHE_SECONDS);
    }

    private static long cacheTtlNanos(long cacheSeconds) {
        if (cacheSeconds < 1 || cacheSeconds > 3600) {
            throw new IllegalArgumentException("JWT JWK cache duration must be between 1 and 3600 seconds");
        }
        return TimeUnit.SECONDS.toNanos(cacheSeconds);
    }

    /** 返回缓存中的当前 JWK Set；缓存过期后只替换完整校验成功的快照。 */
    public JwkSet current() {
        return snapshot().set();
    }

    /** 返回与 JWK 同一快照的 PEM，避免兼容接口再次读取未校验内容。 */
    public String currentPem() {
        return snapshot().pem();
    }

    private CachedKey snapshot() {
        long now = System.nanoTime();
        CachedKey existing = cached;
        if (existing != null && now - existing.loadedAtNanos() < cacheTtlNanos) return existing;
        synchronized (this) {
            now = System.nanoTime();
            existing = cached;
            if (existing != null && now - existing.loadedAtNanos() < cacheTtlNanos) return existing;
            CachedKey loaded = loadSnapshot();
            cached = loaded;
            return loaded;
        }
    }

    /** 单次读取、解析和组装完整快照；任何失败都不会替换上一次已发布的快照。 */
    private CachedKey loadSnapshot() {
        try {
            byte[] pem = readLocation(publicKeyLocation);
            RSAPublicKey publicKey = parseRsaPublicKey(pem);
            var set = new JwkSet(List.of(new RsaJwk(
                    "RSA",
                    keyId,
                    "RS256",
                    "sig",
                    encodeUnsigned(publicKey.getModulus().toByteArray()),
                    encodeUnsigned(publicKey.getPublicExponent().toByteArray()))));
            return new CachedKey(set, new String(pem, StandardCharsets.US_ASCII), System.nanoTime());
        } catch (Exception e) {
            throw unavailable();
        }
    }

    private static RSAPublicKey parseRsaPublicKey(byte[] pem) throws Exception {
        String text = new String(pem, StandardCharsets.US_ASCII).trim();
        if (!text.startsWith(BEGIN_PUBLIC_KEY) || !text.endsWith(END_PUBLIC_KEY)) throw unavailable();
        String body = text.substring(BEGIN_PUBLIC_KEY.length(), text.length() - END_PUBLIC_KEY.length())
                .replaceAll("\\s", "");
        if (body.isBlank()) throw unavailable();
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
        if (!(key instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < 2048) throw unavailable();
        return rsa;
    }

    private static byte[] readLocation(String location) throws IOException {
        if (location.startsWith("classpath:")) {
            return readResource(location.substring("classpath:".length()));
        }
        if (location.startsWith("file:")) {
            return Files.readAllBytes(Paths.get(java.net.URI.create(location)));
        }
        Path path = Paths.get(location);
        if (Files.isRegularFile(path)) return Files.readAllBytes(path);
        return readResource(location);
    }

    private static byte[] readResource(String resourceName) throws IOException {
        String normalized = resourceName == null ? "" : resourceName.trim();
        while (normalized.startsWith("/")) normalized = normalized.substring(1);
        if (normalized.isBlank()) throw unavailable();
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        if (loader == null) loader = JwkSetService.class.getClassLoader();
        try (InputStream stream = loader.getResourceAsStream(normalized)) {
            if (stream == null) throw unavailable();
            return stream.readAllBytes();
        }
    }

    private static String encodeUnsigned(byte[] value) {
        int offset = value.length > 1 && value[0] == 0 ? 1 : 0;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOfRange(value, offset, value.length));
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("JWT public key set is unavailable");
    }

    public record JwkSet(List<RsaJwk> keys) {
        public JwkSet {
            keys = List.copyOf(Objects.requireNonNull(keys, "keys"));
        }
    }

    public record RsaJwk(String kty, String kid, String alg, String use, String n, String e) {}

    private record CachedKey(JwkSet set, String pem, long loadedAtNanos) {}
}
