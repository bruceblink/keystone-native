package app.keystone.auth;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.Cipher;

/** 解码兼容登录输入中的 RSA/PKCS#1 密码；解码失败时不记录或返回明文。 */
@ApplicationScoped
public class LoginPasswordDecoder {
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    private final String privateKeyLocation;
    private volatile RSAPrivateKey privateKey;

    public LoginPasswordDecoder(
            @ConfigProperty(name = "smallrye.jwt.sign.key.location", defaultValue = "") String privateKeyLocation) {
        this.privateKeyLocation = privateKeyLocation == null ? "" : privateKeyLocation.trim();
    }

    /**
     * 普通密码保持现有调用兼容；长度等于 RSA 密文块时按 Base64 RSA 密文处理。
     * 密文解不开时返回空值，调用方统一按错误凭据处理。
     */
    public Optional<String> decode(String value) {
        if (value == null || value.isBlank()) return Optional.empty();

        byte[] encoded;
        try {
            encoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ignored) {
            return Optional.of(value);
        }

        if (encoded.length < 128) return Optional.of(value);

        RSAPrivateKey key = privateKey();
        int blockSize = (key.getModulus().bitLength() + 7) / 8;
        if (encoded.length != blockSize) return Optional.of(value);

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plaintext = cipher.doFinal(encoded);
            String decoded = new String(plaintext, StandardCharsets.UTF_8);
            if (plaintext.length == 0 || !Arrays.equals(decoded.getBytes(StandardCharsets.UTF_8), plaintext)) {
                return Optional.empty();
            }
            return Optional.of(decoded);
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private RSAPrivateKey privateKey() {
        RSAPrivateKey existing = privateKey;
        if (existing != null) return existing;
        synchronized (this) {
            existing = privateKey;
            if (existing == null) {
                existing = loadPrivateKey();
                privateKey = existing;
            }
            return existing;
        }
    }

    private RSAPrivateKey loadPrivateKey() {
        try {
            String text = new String(readLocation(privateKeyLocation), StandardCharsets.US_ASCII).trim();
            if (!text.startsWith(BEGIN_PRIVATE_KEY) || !text.endsWith(END_PRIVATE_KEY)) throw unavailable();
            String body = text.substring(BEGIN_PRIVATE_KEY.length(), text.length() - END_PRIVATE_KEY.length())
                    .replaceAll("\\s", "");
            PrivateKey key = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            if (!(key instanceof RSAPrivateKey rsa) || rsa.getModulus().bitLength() < 2048) throw unavailable();
            return rsa;
        } catch (Exception e) {
            throw unavailable();
        }
    }

    private static byte[] readLocation(String location) throws IOException {
        if (location == null || location.isBlank()) throw unavailable();
        if (location.startsWith("classpath:")) return readResource(location.substring("classpath:".length()));
        if (location.startsWith("file:")) return Files.readAllBytes(Paths.get(java.net.URI.create(location)));
        Path path = Paths.get(location);
        if (Files.isRegularFile(path)) return Files.readAllBytes(path);
        return readResource(location);
    }

    private static byte[] readResource(String resourceName) throws IOException {
        String normalized = resourceName == null ? "" : resourceName.trim();
        while (normalized.startsWith("/")) normalized = normalized.substring(1);
        if (normalized.isBlank()) throw unavailable();
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        if (loader == null) loader = LoginPasswordDecoder.class.getClassLoader();
        try (InputStream stream = loader.getResourceAsStream(normalized)) {
            if (stream == null) throw unavailable();
            return stream.readAllBytes();
        }
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("JWT signing key is unavailable");
    }
}
