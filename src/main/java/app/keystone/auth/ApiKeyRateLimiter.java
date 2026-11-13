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
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_api_key_rate_limit WHERE scope_key IN (?, ?)")) {
            var dimensions = keys(value, ipAddress);
            p.setString(1, dimensions.get(0)); p.setString(2, dimensions.get(1)); p.executeUpdate();
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
        Instant now = Instant.now();
        int attempts = 1;
        Timestamp windowStarted = Timestamp.from(now);
        try (var find = c.prepareStatement("SELECT window_started_at, attempt_count FROM sys_api_key_rate_limit WHERE scope_key = ? FOR UPDATE")) {
            find.setString(1, key);
            try (var rs = find.executeQuery()) {
                if (rs.next()) {
                    Timestamp existingWindow = rs.getTimestamp(1);
                    if (existingWindow != null && existingWindow.toInstant().plusSeconds(windowSeconds).isAfter(now)) {
                        attempts = rs.getInt(2) + 1;
                        windowStarted = existingWindow;
                    }
                }
            }
        }
        Timestamp blockedUntil = attempts >= maxFailures ? Timestamp.from(now.plusSeconds(blockSeconds)) : null;
        try (var update = c.prepareStatement("INSERT INTO sys_api_key_rate_limit(scope_key, window_started_at, attempt_count, blocked_until) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE window_started_at = VALUES(window_started_at), attempt_count = VALUES(attempt_count), blocked_until = VALUES(blocked_until)")) {
            update.setString(1, key); update.setTimestamp(2, windowStarted); update.setInt(3, attempts);
            if (blockedUntil == null) update.setNull(4, java.sql.Types.TIMESTAMP); else update.setTimestamp(4, blockedUntil);
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
