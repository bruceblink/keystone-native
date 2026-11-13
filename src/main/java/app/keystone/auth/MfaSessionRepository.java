package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;

/** 使用会话 ORM 保存和读取 MFA 二次验证状态，不直接访问 JDBC。 */
@ApplicationScoped
public class MfaSessionRepository {
    private static final int MAX_ASSURANCE_LENGTH = 32;
    private static final int MAX_AMR_LENGTH = 128;
    private static final Duration MAX_VERIFICATION_AGE = Duration.ofHours(24);

    @Inject AuthSessionRepository sessions;

    /** 为活动会话写入最近一次 MFA 验证结果。 */
    @Transactional
    public boolean markVerified(String sessionId, String userId, String clientId, String assurance, String amr) {
        String boundSessionId = requiredIdentifier(sessionId, "sessionId", 64);
        String boundClientId = requiredClientId(clientId);
        String boundAssurance = requiredToken(assurance, "assurance", MAX_ASSURANCE_LENGTH);
        String boundAmr = requiredToken(amr, "amr", MAX_AMR_LENGTH);
        app.keystone.identity.UuidValues.requireCanonical(userId);

        Instant now = Instant.now();
        AuthSessionEntity session = sessions.findForUpdate(boundSessionId);
        if (session == null || !userId.equals(session.userId()) || !session.clientId().equals(boundClientId)
                || !session.activeAt(now)) return false;
        session.markMfaVerified(now, boundAssurance, boundAmr);
        return true;
    }

    /** 检查会话是否在指定时间内完成了指定认证强度的 MFA 验证。 */
    @Transactional
    public boolean hasRecentStepUp(String sessionId, String userId, String clientId, Duration maxAge,
                                   String requiredAssurance) {
        String boundSessionId = requiredIdentifier(sessionId, "sessionId", 64);
        String boundClientId = requiredClientId(clientId);
        String boundAssurance = requiredToken(requiredAssurance, "requiredAssurance", MAX_ASSURANCE_LENGTH);
        app.keystone.identity.UuidValues.requireCanonical(userId);
        if (maxAge == null || maxAge.isZero() || maxAge.isNegative() || maxAge.compareTo(MAX_VERIFICATION_AGE) > 0) {
            throw new IllegalArgumentException("maxAge must be between one second and twenty-four hours");
        }

        Instant now = Instant.now();
        AuthSessionEntity session = sessions.findById(boundSessionId);
        return session != null
                && userId.equals(session.userId())
                && session.clientId().equals(boundClientId)
                && session.activeAt(now)
                && session.mfaVerifiedAt() != null
                && !session.mfaVerifiedAt().isBefore(now.minus(maxAge))
                && boundAssurance.equals(session.mfaAssurance());
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
