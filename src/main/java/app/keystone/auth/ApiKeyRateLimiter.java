package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/** Limits repeated invalid API Key attempts by source and credential dimensions. */
@ApplicationScoped
public class ApiKeyRateLimiter {
    @Inject ApiKeyRateLimitRepository repository;
    @ConfigProperty(name = "keystone.security.api-key.rate-limit.max-failures", defaultValue = "20") int maxFailures;
    @ConfigProperty(name = "keystone.security.api-key.rate-limit.window-seconds", defaultValue = "60") long windowSeconds;
    @ConfigProperty(name = "keystone.security.api-key.rate-limit.block-seconds", defaultValue = "300") long blockSeconds;

    @Transactional
    public boolean isBlocked(String value, String ipAddress) {
        validate(value, ipAddress);
        validateConfig();
        try {
            Instant now = Instant.now();
            for (String key : keys(value, ipAddress)) {
                var row = repository.findByScopeKey(key);
                if (row != null && row.isBlockedAt(now)) return true;
            }
            return false;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not check API key rate limit", e);
        }
    }

    @Transactional
    public void recordFailure(String value, String ipAddress) {
        validate(value, ipAddress);
        validateConfig();
        try {
            Instant now = Instant.now();
            repository.deleteExpired(now.minusSeconds(windowSeconds), now);
            for (String key : keys(value, ipAddress)) increment(key, now);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not record API key failure", e);
        }
    }

    @Transactional
    public void clear(String value, String ipAddress) {
        validate(value, ipAddress);
        validateConfig();
        try {
            var dimensions = keys(value, ipAddress);
            // 成功认证只清理当前凭据桶；来源地址桶必须保留，避免一个有效 key 清空其他调用方的失败记录。
            repository.deleteByScopeKey(dimensions.get(1));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not clear API key rate limit", e);
        }
    }

    static List<String> keys(String value, String ipAddress) {
        return List.of(hash("ip:" + normalize(ipAddress, "unknown")), hash("key:" + normalize(value, "unknown")));
    }

    private void increment(String key, Instant now) {
        var row = repository.findForUpdate(key);
        if (row == null) {
            Instant blockedUntil = maxFailures <= 1 ? now.plusSeconds(blockSeconds) : null;
            repository.persistAndFlush(new ApiKeyRateLimitEntity(key, now, 1, blockedUntil));
            return;
        }
        boolean currentWindow = row.windowStartedAt() != null
                && row.windowStartedAt().plusSeconds(windowSeconds).isAfter(now);
        int attempts = currentWindow ? row.attemptCount() + 1 : 1;
        Instant windowStartedAt = currentWindow ? row.windowStartedAt() : now;
        Instant blockedUntil = attempts >= maxFailures ? now.plusSeconds(blockSeconds) : null;
        row.update(windowStartedAt, attempts, blockedUntil);
    }

    private void validateConfig() {
        if (maxFailures <= 0 || windowSeconds <= 0 || blockSeconds <= 0) throw new IllegalStateException("API key rate limit configuration must be positive");
    }

    private static void validate(String value, String ipAddress) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("API key is required");
        if (ipAddress == null || ipAddress.isBlank()) throw new IllegalArgumentException("client address is required");
    }

    private static String normalize(String value, String fallback) { return value == null || value.isBlank() ? fallback : value.trim(); }
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); }
    }
}
