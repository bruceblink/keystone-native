package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/** Limits repeated invalid API Key attempts by source and credential dimensions. */
@ApplicationScoped
public class ApiKeyRateLimiter {
    @Inject DataSource dataSource;
    @ConfigProperty(name = "keystone.security.api-key.rate-limit.max-failures", defaultValue = "20") int maxFailures;
    @ConfigProperty(name = "keystone.security.api-key.rate-limit.window-seconds", defaultValue = "60") long windowSeconds;
    @ConfigProperty(name = "keystone.security.api-key.rate-limit.block-seconds", defaultValue = "300") long blockSeconds;

    public boolean isBlocked(String value, String ipAddress) {
        validate(value, ipAddress);
        validateConfig();
        try (var c = dataSource.getConnection()) {
            for (String key : keys(value, ipAddress)) if (blocked(c, key)) return true;
            return false;
        } catch (Exception e) { throw new IllegalStateException("Could not check API key rate limit", e); }
    }

    public void recordFailure(String value, String ipAddress) {
        validate(value, ipAddress);
        validateConfig();
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                cleanup(c);
                for (String key : keys(value, ipAddress)) increment(c, key);
                c.commit();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (Exception e) { throw new IllegalStateException("Could not record API key failure", e); }
    }

    public void clear(String value, String ipAddress) {
        validate(value, ipAddress);
        validateConfig();
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_api_key_rate_limit WHERE scope_key = ?")) {
            var dimensions = keys(value, ipAddress);
            // 成功认证只清理当前凭据桶；来源地址桶必须保留，避免一个有效 key 清空其他调用方的失败记录。
            p.setString(1, dimensions.get(1)); p.executeUpdate();
        } catch (Exception e) { throw new IllegalStateException("Could not clear API key rate limit", e); }
    }

    static List<String> keys(String value, String ipAddress) {
        return List.of(hash("ip:" + normalize(ipAddress, "unknown")), hash("key:" + normalize(value, "unknown")));
    }

    private boolean blocked(java.sql.Connection c, String key) throws Exception {
        try (var p = c.prepareStatement("SELECT blocked_until FROM sys_api_key_rate_limit WHERE scope_key = ?")) {
            p.setString(1, key);
            try (var rs = p.executeQuery()) {
                if (!rs.next()) return false;
                Timestamp blockedUntil = rs.getTimestamp(1);
                return blockedUntil != null && blockedUntil.toInstant().isAfter(Instant.now());
            }
        }
    }

    private void increment(java.sql.Connection c, String key) throws Exception {
        String sql = """
                INSERT INTO sys_api_key_rate_limit(scope_key, window_started_at, attempt_count, blocked_until)
                VALUES (?, CURRENT_TIMESTAMP, 1, IF(1 >= ?, TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP), NULL))
                ON DUPLICATE KEY UPDATE
                attempt_count = IF(window_started_at < TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP), 1, attempt_count + 1),
                window_started_at = IF(window_started_at < TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP, window_started_at),
                blocked_until = IF(attempt_count >= ?, TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP), NULL)
                """;
        try (var update = c.prepareStatement(sql)) {
            update.setString(1, key);
            update.setInt(2, maxFailures);
            update.setLong(3, blockSeconds);
            update.setLong(4, windowSeconds);
            update.setLong(5, windowSeconds);
            update.setInt(6, maxFailures);
            update.setLong(7, blockSeconds);
            update.executeUpdate();
        }
    }

    private void cleanup(java.sql.Connection c) throws Exception {
        try (var p = c.prepareStatement("DELETE FROM sys_api_key_rate_limit WHERE (blocked_until IS NULL AND window_started_at < TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP)) OR (blocked_until IS NOT NULL AND blocked_until < CURRENT_TIMESTAMP)")) {
            p.setLong(1, windowSeconds); p.executeUpdate();
        }
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
