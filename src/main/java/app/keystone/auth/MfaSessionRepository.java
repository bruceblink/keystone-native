package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.sql.DataSource;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;

/**
 * 保存并读取会话的 MFA 二次验证状态。
 *
 * <p>所有写入和读取都同时绑定会话、用户和客户端，并且只接受仍然有效的会话。
 * 数据库不可用时抛出失败关闭异常，调用方不得回退到令牌中的旧状态。</p>
 */
@ApplicationScoped
public class MfaSessionRepository {
    private static final int MAX_ASSURANCE_LENGTH = 32;
    private static final int MAX_AMR_LENGTH = 128;
    private static final Duration MAX_VERIFICATION_AGE = Duration.ofHours(24);

    @Inject DataSource dataSource;

    /**
     * 为活动会话写入最近一次 MFA 验证结果。
     *
     * @return 会话存在、未撤销且仍在有效期内时返回 true
     */
    public boolean markVerified(String sessionId, long userId, String clientId, String assurance, String amr) {
        String boundSessionId = requiredIdentifier(sessionId, "sessionId", 64);
        String boundClientId = requiredClientId(clientId);
        String boundAssurance = requiredToken(assurance, "assurance", MAX_ASSURANCE_LENGTH);
        String boundAmr = requiredToken(amr, "amr", MAX_AMR_LENGTH);
        if (userId <= 0) throw new IllegalArgumentException("userId must be positive");
        try (var c = dataSource.getConnection();
             var p = c.prepareStatement("UPDATE sys_auth_session SET mfa_verified_at = CURRENT_TIMESTAMP, mfa_assurance = ?, mfa_amr = ? WHERE id = ? AND user_id = ? AND client_id = ? AND revoked_at IS NULL AND refresh_expires_at > CURRENT_TIMESTAMP AND idle_expires_at > CURRENT_TIMESTAMP")) {
            p.setString(1, boundAssurance);
            p.setString(2, boundAmr);
            p.setString(3, boundSessionId);
            p.setLong(4, userId);
            p.setString(5, boundClientId);
            return p.executeUpdate() == 1;
        } catch (Exception e) {
            throw new IllegalStateException("Could not record MFA session state", e);
        }
    }

    /**
     * 检查会话是否在指定时间内完成了指定认证强度的 MFA 验证。
     * 时间边界由应用计算并绑定为参数，避免把外部秒数拼接到 SQL 中。
     */
    public boolean hasRecentStepUp(String sessionId, long userId, String clientId, Duration maxAge, String requiredAssurance) {
        String boundSessionId = requiredIdentifier(sessionId, "sessionId", 64);
        String boundClientId = requiredClientId(clientId);
        String boundAssurance = requiredToken(requiredAssurance, "requiredAssurance", MAX_ASSURANCE_LENGTH);
        if (userId <= 0) throw new IllegalArgumentException("userId must be positive");
        if (maxAge == null || maxAge.isZero() || maxAge.isNegative() || maxAge.compareTo(MAX_VERIFICATION_AGE) > 0) {
            throw new IllegalArgumentException("maxAge must be between one second and twenty-four hours");
        }
        Instant cutoff;
        try {
            cutoff = Instant.now().minus(maxAge);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("maxAge is outside the supported range", e);
        }
        try (var c = dataSource.getConnection();
             var p = c.prepareStatement("SELECT 1 FROM sys_auth_session WHERE id = ? AND user_id = ? AND client_id = ? AND revoked_at IS NULL AND refresh_expires_at > CURRENT_TIMESTAMP AND idle_expires_at > CURRENT_TIMESTAMP AND mfa_verified_at IS NOT NULL AND mfa_verified_at >= ? AND mfa_assurance = ?")) {
            p.setString(1, boundSessionId);
            p.setLong(2, userId);
            p.setString(3, boundClientId);
            p.setTimestamp(4, Timestamp.from(cutoff));
            p.setString(5, boundAssurance);
            try (var rs = p.executeQuery()) {
                return rs.next();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not validate MFA session state", e);
        }
    }

    private static String requiredIdentifier(String value, String field, int maxLength) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
        String normalized = value.trim();
        if (normalized.length() > maxLength || !normalized.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0," + (maxLength - 1) + "}")) {
            throw new IllegalArgumentException("invalid " + field);
        }
        return normalized;
    }

    private static String requiredClientId(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("clientId is required");
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) throw new IllegalArgumentException("invalid clientId");
        return normalized;
    }

    private static String requiredToken(String value, String field, int maxLength) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
        String normalized = value.trim();
        if (normalized.length() > maxLength || !normalized.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0," + (maxLength - 1) + "}")) {
            throw new IllegalArgumentException("invalid " + field);
        }
        return normalized;
    }
}
