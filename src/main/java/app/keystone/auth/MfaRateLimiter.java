package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
    @Inject MfaRateLimitRepository repository;
    @ConfigProperty(name = "keystone.security.mfa.rate-limit.max-failures", defaultValue = "5")
    int maxFailures;
    @ConfigProperty(name = "keystone.security.mfa.rate-limit.window-seconds", defaultValue = "60")
    long windowSeconds;
    @ConfigProperty(name = "keystone.security.mfa.rate-limit.block-seconds", defaultValue = "300")
    long blockSeconds;

    /** 在 MFA 验证前检查主体和地址是否处于阻断期。 */
    @Transactional
    public boolean isBlocked(long userId, String ipAddress) {
        validateConfig(userId);
        try {
            Instant now = Instant.now();
            for (String key : keys(userId, ipAddress)) {
                MfaRateLimitEntity row = repository.findByScopeKey(key);
                if (row != null && row.isBlockedAt(now)) return true;
            }
            return false;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not check MFA rate limit", e);
        }
    }

    /** 在一个事务中原子增加主体和地址两个维度的失败次数。 */
    @Transactional
    public void recordFailure(long userId, String ipAddress) {
        validateConfig(userId);
        try {
            Instant now = Instant.now();
            repository.deleteExpired(now.minusSeconds(windowSeconds), now);
            for (String key : keys(userId, ipAddress)) increment(key, now);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not record MFA failure rate", e);
        }
    }

    /** MFA 验证成功后只清除主体维度；地址维度保留到窗口结束。 */
    @Transactional
    public void clear(long userId, String ipAddress) {
        validateConfig(userId);
        try {
            repository.deleteByScopeKey(keys(userId, ipAddress).get(0));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not clear MFA rate limit", e);
        }
    }

    private void increment(String key, Instant now) {
        MfaRateLimitEntity row = repository.findForUpdate(key);
        if (row == null) {
            Instant blockedUntil = maxFailures <= 1 ? now.plusSeconds(blockSeconds) : null;
            repository.persistAndFlush(new MfaRateLimitEntity(key, now, 1, blockedUntil));
            return;
        }
        boolean currentWindow = row.windowStartedAt() != null
                && row.windowStartedAt().plusSeconds(windowSeconds).isAfter(now);
        int attempts = currentWindow ? row.attemptCount() + 1 : 1;
        Instant windowStartedAt = currentWindow ? row.windowStartedAt() : now;
        Instant blockedUntil = attempts >= maxFailures ? now.plusSeconds(blockSeconds) : null;
        row.update(windowStartedAt, attempts, blockedUntil);
    }

    /** 测试和启动检查使用的配置边界；用户 ID 也必须绑定到已解析的主体。 */
    private void validateConfig(long userId) {
        if (userId <= 0) throw new IllegalArgumentException("userId must be positive");
        if (maxFailures <= 0 || windowSeconds <= 0 || blockSeconds <= 0) {
            throw new IllegalStateException("MFA rate limit configuration must be positive");
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
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
