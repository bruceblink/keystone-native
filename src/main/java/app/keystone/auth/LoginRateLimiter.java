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

/**
 * 使用数据库记录登录失败窗口，按 IP 和用户名分别限制请求。
 * 计数只保存哈希键，不保存原始地址或用户名，适合多节点部署。
 */
@ApplicationScoped
public class LoginRateLimiter {
    @Inject DataSource dataSource;
    @ConfigProperty(name = "keystone.security.login.max-failures", defaultValue = "10") int maxFailures;
    @ConfigProperty(name = "keystone.security.login.window-seconds", defaultValue = "60") long windowSeconds;
    @ConfigProperty(name = "keystone.security.login.block-seconds", defaultValue = "300") long blockSeconds;

    /** 在认证前判断两个维度是否仍处于阻断期。 */
    public boolean isBlocked(String username, String ipAddress) {
        validateConfig();
        try (var c = dataSource.getConnection()) {
            for (String key : keys(username, ipAddress)) if (blocked(c, key)) return true;
            return false;
        } catch (Exception e) {
            throw new IllegalStateException("Could not check login rate limit", e);
        }
    }

    /** 认证失败后原子增加两个维度的计数，达到阈值后写入阻断时间。 */
    public void recordFailure(String username, String ipAddress) {
        validateConfig();
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                cleanup(c);
                for (String key : keys(username, ipAddress)) increment(c, key);
                c.commit();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (Exception e) {
            throw new IllegalStateException("Could not record login failure", e);
        }
    }

    /** 成功认证后清除相同的两个限流维度，避免历史失败影响正常使用。 */
    public void clear(String username, String ipAddress) {
        validateConfig();
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_login_rate_limit WHERE scope_key IN (?, ?)")) {
            var keys = keys(username, ipAddress);
            p.setString(1, keys.get(0)); p.setString(2, keys.get(1)); p.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("Could not clear login rate limit", e);
        }
    }

    private boolean blocked(java.sql.Connection c, String key) throws Exception {
        try (var p = c.prepareStatement("SELECT blocked_until FROM sys_login_rate_limit WHERE scope_key = ?")) {
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
        try (var find = c.prepareStatement("SELECT window_started_at, attempt_count FROM sys_login_rate_limit WHERE scope_key = ? FOR UPDATE")) {
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
        try (var update = c.prepareStatement("INSERT INTO sys_login_rate_limit(scope_key, window_started_at, attempt_count, blocked_until) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE window_started_at = VALUES(window_started_at), attempt_count = VALUES(attempt_count), blocked_until = VALUES(blocked_until)")) {
            update.setString(1, key); update.setTimestamp(2, windowStarted); update.setInt(3, attempts); if (blockedUntil == null) update.setNull(4, java.sql.Types.TIMESTAMP); else update.setTimestamp(4, blockedUntil); update.executeUpdate();
        }
    }

    /** 清理已经离开窗口的记录，避免攻击者使用大量新标识造成表无限增长。 */
    private void cleanup(java.sql.Connection c) throws Exception {
        try (var p = c.prepareStatement("DELETE FROM sys_login_rate_limit WHERE (blocked_until IS NULL AND window_started_at < TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP)) OR (blocked_until IS NOT NULL AND blocked_until < CURRENT_TIMESTAMP)")) {
            p.setLong(1, windowSeconds); p.executeUpdate();
        }
    }

    private void validateConfig() {
        if (maxFailures <= 0 || windowSeconds <= 0 || blockSeconds <= 0) throw new IllegalStateException("login rate limit configuration must be positive");
    }

    private static List<String> keys(String username, String ipAddress) {
        return List.of(hash("ip:" + normalize(ipAddress, "unknown")), hash("user:" + normalize(username, "unknown").toLowerCase(java.util.Locale.ROOT)));
    }

    private static String normalize(String value, String fallback) { return value == null || value.isBlank() ? fallback : value.trim(); }

    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); }
    }
}
