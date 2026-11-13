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

/** 使用数据库记录登录失败窗口，按 IP 和用户名分别限制请求。 */
@ApplicationScoped
public class LoginRateLimiter {
    @Inject LoginRateLimitRepository repository;
    @ConfigProperty(name = "keystone.security.login.max-failures", defaultValue = "10") int maxFailures;
    @ConfigProperty(name = "keystone.security.login.window-seconds", defaultValue = "60") long windowSeconds;
    @ConfigProperty(name = "keystone.security.login.block-seconds", defaultValue = "300") long blockSeconds;

    /** 在认证前判断两个维度是否仍处于阻断期。 */
    @Transactional
    public boolean isBlocked(String username, String ipAddress) {
        validateConfig();
        try {
            Instant now = Instant.now();
            for (String key : keys(username, ipAddress)) {
                var row = repository.findByScopeKey(key);
                if (row != null && row.isBlockedAt(now)) return true;
            }
            return false;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not check login rate limit", e);
        }
    }

    /** 认证失败后原子增加两个维度的计数，达到阈值后写入阻断时间。 */
    @Transactional
    public void recordFailure(String username, String ipAddress) {
        validateConfig();
        try {
            Instant now = Instant.now();
            repository.deleteExpired(now.minusSeconds(windowSeconds), now);
            for (String key : keys(username, ipAddress)) increment(key, now);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not record login failure", e);
        }
    }

    /** 成功认证后清除相同的两个限流维度，避免历史失败影响正常使用。 */
    @Transactional
    public void clear(String username, String ipAddress) {
        validateConfig();
        try {
            var dimensions = keys(username, ipAddress);
            repository.deleteByScopeKey(dimensions.get(0));
            repository.deleteByScopeKey(dimensions.get(1));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not clear login rate limit", e);
        }
    }

    static List<String> keys(String username, String ipAddress) {
        return List.of(hash("ip:" + normalize(ipAddress, "unknown")),
                hash("user:" + normalize(username, "unknown").toLowerCase(java.util.Locale.ROOT)));
    }

    private void increment(String key, Instant now) {
        var row = repository.findForUpdate(key);
        if (row == null) {
            Instant blockedUntil = maxFailures <= 1 ? now.plusSeconds(blockSeconds) : null;
            repository.persistAndFlush(new LoginRateLimitEntity(key, now, 1, blockedUntil));
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
        if (maxFailures <= 0 || windowSeconds <= 0 || blockSeconds <= 0) {
            throw new IllegalStateException("login rate limit configuration must be positive");
        }
    }

    private static String normalize(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
