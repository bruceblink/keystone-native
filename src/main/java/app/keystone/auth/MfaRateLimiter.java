package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.sql.DataSource;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * 对 MFA 验证失败执行主体和来源地址双维度限流。
 *
 * <p>数据库只保存哈希后的维度键。主体键限制同一账户的失败次数，地址键限制
 * 同一来源的失败次数。两个维度都被阻断时，验证入口统一返回失败，避免暴露阻断原因。</p>
 */
@ApplicationScoped
public class MfaRateLimiter {
    @Inject DataSource dataSource;
    @ConfigProperty(name = "keystone.security.mfa.rate-limit.max-failures", defaultValue = "5")
    int maxFailures;
    @ConfigProperty(name = "keystone.security.mfa.rate-limit.window-seconds", defaultValue = "60")
    long windowSeconds;
    @ConfigProperty(name = "keystone.security.mfa.rate-limit.block-seconds", defaultValue = "300")
    long blockSeconds;

    /** 在 MFA 验证前检查主体和地址是否处于阻断期。 */
    public boolean isBlocked(long userId, String ipAddress) {
        validateConfig(userId);
        try (var c = dataSource.getConnection()) {
            for (String key : keys(userId, ipAddress)) {
                if (blocked(c, key)) return true;
            }
            return false;
        } catch (Exception e) {
            throw new IllegalStateException("Could not check MFA rate limit", e);
        }
    }

    /** 在一个事务中原子增加主体和地址两个维度的失败次数。 */
    public void recordFailure(long userId, String ipAddress) {
        validateConfig(userId);
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                cleanup(c);
                for (String key : keys(userId, ipAddress)) increment(c, key);
                c.commit();
            } catch (Exception e) {
                c.rollback();
                throw e;
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not record MFA failure rate", e);
        }
    }

    /** MFA 验证成功后只清除主体维度；地址维度保留到窗口结束，避免一个用户成功清空其他用户的来源限流。 */
    public void clear(long userId, String ipAddress) {
        validateConfig(userId);
        try (var c = dataSource.getConnection();
             var p = c.prepareStatement("DELETE FROM sys_mfa_rate_limit WHERE scope_key = ?")) {
            var dimensions = keys(userId, ipAddress);
            p.setString(1, dimensions.get(0));
            p.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("Could not clear MFA rate limit", e);
        }
    }

    /** 测试和启动检查使用的配置边界；用户 ID 也必须绑定到已解析的主体。 */
    private void validateConfig(long userId) {
        if (userId <= 0) throw new IllegalArgumentException("userId must be positive");
        if (maxFailures <= 0 || windowSeconds <= 0 || blockSeconds <= 0) {
            throw new IllegalStateException("MFA rate limit configuration must be positive");
        }
    }

    private boolean blocked(java.sql.Connection c, String key) throws Exception {
        try (var p = c.prepareStatement("SELECT blocked_until FROM sys_mfa_rate_limit WHERE scope_key = ?")) {
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
        try (var find = c.prepareStatement("SELECT window_started_at, attempt_count FROM sys_mfa_rate_limit WHERE scope_key = ? FOR UPDATE")) {
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
        try (var update = c.prepareStatement("INSERT INTO sys_mfa_rate_limit(scope_key, window_started_at, attempt_count, blocked_until) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE window_started_at = VALUES(window_started_at), attempt_count = VALUES(attempt_count), blocked_until = VALUES(blocked_until)")) {
            update.setString(1, key);
            update.setTimestamp(2, windowStarted);
            update.setInt(3, attempts);
            if (blockedUntil == null) update.setNull(4, java.sql.Types.TIMESTAMP); else update.setTimestamp(4, blockedUntil);
            update.executeUpdate();
        }
    }

    /** 清理过期记录，避免长期失败来源让限流表无限增长。 */
    private void cleanup(java.sql.Connection c) throws Exception {
        try (var p = c.prepareStatement("DELETE FROM sys_mfa_rate_limit WHERE (blocked_until IS NULL AND window_started_at < TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP)) OR (blocked_until IS NOT NULL AND blocked_until < CURRENT_TIMESTAMP)")) {
            p.setLong(1, windowSeconds);
            p.executeUpdate();
        }
    }

    /** 维度键始终经过哈希，调用方不会把主体或来源地址写入数据库。 */
    static List<String> keys(long userId, String ipAddress) {
        return List.of(hash("mfa:user:" + userId), hash("mfa:ip:" + normalizeIp(ipAddress)));
    }

    /** 只接受单个地址值或可信代理链的首个地址，长度和字符均受限。 */
    static String normalizeIp(String value) {
        String normalized = value == null || value.isBlank() ? "unknown" : value.trim();
        int comma = normalized.indexOf(',');
        if (comma >= 0) normalized = normalized.substring(0, comma).trim();
        if (normalized.startsWith("[") && normalized.endsWith("]")) normalized = normalized.substring(1, normalized.length() - 1);
        if (normalized.length() > 64 || normalized.isBlank() || "unknown".equalsIgnoreCase(normalized)) return "unknown";
        if (!isLiteralAddress(normalized)) return "unknown";
        try { return InetAddress.getByName(normalized).getHostAddress().toLowerCase(Locale.ROOT); }
        catch (java.io.IOException e) { return "unknown"; }
    }

    private static boolean isLiteralAddress(String value) {
        if (value.matches("[0-9.]+")) {
            String[] octets = value.split("\\.", -1);
            if (octets.length != 4) return false;
            for (String octet : octets) {
                try { if (octet.isBlank() || Integer.parseInt(octet) > 255) return false; }
                catch (NumberFormatException e) { return false; }
            }
            return true;
        }
        return value.indexOf(':') >= 0 && value.matches("[0-9A-Fa-f:]+") && value.length() <= 39;
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
