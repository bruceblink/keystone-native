package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** 保存和消费 MFA 认证请求。 */
@ApplicationScoped
public class MfaChallengeRepository {
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(10);
    private static final int DEFAULT_MAX_ATTEMPTS = 5;

    @Inject AuthChallengeOrmRepository repository;

    /** 创建短期认证请求；上下文摘要只保存在数据库内部。 */
    @Transactional
    public Challenge create(long userId, Purpose purpose, String clientId, String sessionId,
                            String contextHash, Instant expiresAt) {
        requireUser(userId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedClientId = normalizeClientId(clientId);
        String checkedSessionId = normalizeSessionId(sessionId);
        String checkedContextHash = normalizeContextHash(contextHash);
        Instant checkedExpiry = requireExpiry(expiresAt);
        String id = UUID.randomUUID().toString();
        repository.persistAndFlush(new AuthChallengeEntity(id, userId, checkedPurpose.value(), checkedClientId,
                checkedSessionId, checkedContextHash, checkedExpiry));
        return new Challenge(id, userId, checkedPurpose, checkedClientId, checkedSessionId, checkedExpiry, 0, null);
    }

    /** 按主体、客户端、用途和会话读取仍可用的认证请求。 */
    @Transactional
    public List<Challenge> findActive(long userId, String clientId, Purpose purpose, String sessionId) {
        requireUser(userId);
        String checkedClientId = normalizeClientId(clientId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedSessionId = normalizeSessionId(sessionId);
        Instant now = Instant.now();
        return repository.listActive(userId, checkedClientId, checkedPurpose.value(), checkedSessionId,
                        now, DEFAULT_MAX_ATTEMPTS).stream().map(this::toChallenge).toList();
    }

    /** 按不透明 ID 和绑定条件读取单个仍可用的认证请求。 */
    @Transactional
    public Optional<Challenge> findActive(String challengeId, long userId, String clientId,
                                          Purpose purpose, String sessionId) {
        requireUser(userId);
        String checkedId = normalizeChallengeId(challengeId);
        String checkedClientId = normalizeClientId(clientId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedSessionId = normalizeSessionId(sessionId);
        AuthChallengeEntity entity = repository.findActive(checkedId, userId, checkedClientId,
                checkedPurpose.value(), checkedSessionId, Instant.now(), DEFAULT_MAX_ATTEMPTS);
        return entity == null ? Optional.empty() : Optional.of(toChallenge(entity));
    }

    /** 在调用方事务内锁定仍可消费的认证请求。 */
    Optional<Challenge> lockActiveForUpdate(String challengeId, long userId, String clientId,
                                             Purpose purpose, String sessionId) {
        requireUser(userId);
        String checkedId = normalizeChallengeId(challengeId);
        String checkedClientId = normalizeClientId(clientId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedSessionId = normalizeSessionId(sessionId);
        AuthChallengeEntity entity = repository.findActiveForUpdate(checkedId, userId, checkedClientId,
                checkedPurpose.value(), checkedSessionId, Instant.now(), DEFAULT_MAX_ATTEMPTS);
        return entity == null ? Optional.empty() : Optional.of(toChallenge(entity));
    }

    /** 消费已经在同一事务中锁定并重新核验过的认证请求。 */
    boolean consumeLocked(Challenge challenge) {
        if (challenge == null) throw new IllegalArgumentException("challenge is required");
        AuthChallengeEntity entity = repository.findById(challenge.id());
        if (entity == null || entity.userId() != challenge.userId()) return false;
        return entity.consume(Instant.now(), DEFAULT_MAX_ATTEMPTS);
    }

    /** 原子消费认证请求；过期、重复消费和失败次数超限都会失败。 */
    @Transactional
    public boolean consume(String challengeId, long userId, String clientId, Purpose purpose, String sessionId) {
        var challenge = lockActiveForUpdate(challengeId, userId, clientId, purpose, sessionId);
        return challenge.isPresent() && consumeLocked(challenge.get());
    }

    /** 原子增加失败次数；达到上限后不再修改状态。 */
    @Transactional
    public boolean recordFailure(String challengeId, long userId, String clientId, Purpose purpose, String sessionId) {
        var challenge = lockActiveForUpdate(challengeId, userId, clientId, purpose, sessionId);
        if (challenge.isEmpty()) return false;
        AuthChallengeEntity entity = repository.findById(challenge.get().id());
        return entity != null && entity.recordFailure(Instant.now(), DEFAULT_MAX_ATTEMPTS);
    }

    private Challenge toChallenge(AuthChallengeEntity entity) {
        return new Challenge(entity.id(), entity.userId(), Purpose.from(entity.purpose()), entity.clientId(),
                entity.sessionId(), entity.expiresAt(), entity.attemptCount(), entity.consumedAt());
    }

    private static Instant requireExpiry(Instant value) {
        if (value == null) throw new IllegalArgumentException("expiresAt is required");
        Instant now = Instant.now();
        if (!value.isAfter(now) || value.isAfter(now.plus(MAX_LIFETIME))) {
            throw new IllegalArgumentException("expiresAt must be within ten minutes");
        }
        return value;
    }

    private static Purpose requirePurpose(Purpose value) {
        if (value == null) throw new IllegalArgumentException("purpose is required");
        return value;
    }

    private static void requireUser(long value) {
        if (value <= 0) throw new IllegalArgumentException("userId must be positive");
    }

    private static String normalizeChallengeId(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("challengeId is required");
        try {
            return UUID.fromString(value.trim()).toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("challengeId must be a UUID");
        }
    }

    private static String normalizeClientId(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("clientId is required");
        String normalized = value.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) throw new IllegalArgumentException("invalid clientId");
        return normalized;
    }

    private static String normalizeSessionId(String value) {
        if (value == null || value.isBlank()) return null;
        String normalized = value.trim();
        if (normalized.length() > 36 || !normalized.matches("[A-Za-z0-9-]+")) throw new IllegalArgumentException("invalid sessionId");
        return normalized;
    }

    private static String normalizeContextHash(String value) {
        if (value == null || value.isBlank()) return null;
        String normalized = value.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("contextHash must be SHA-256 hex");
        return normalized;
    }

    public enum Purpose {
        LOGIN("LOGIN"), STEP_UP("STEP_UP"), ENROLL("ENROLL"), RECOVERY("RECOVERY");

        private final String value;

        Purpose(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }

        private static Purpose from(String value) {
            for (Purpose purpose : values()) if (purpose.value.equals(value)) return purpose;
            throw new IllegalStateException("Unknown MFA purpose");
        }
    }

    public record Challenge(String id, long userId, Purpose purpose, String clientId, String sessionId,
                            Instant expiresAt, int attemptCount, Instant consumedAt) {
    }
}
