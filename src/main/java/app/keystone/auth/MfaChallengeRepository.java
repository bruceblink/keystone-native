package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.sql.DataSource;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 保存和消费 MFA 挑战。
 *
 * <p>挑战 ID 是唯一的不透明标识。数据库只保存上下文摘要，不把原始上下文返回给调用方。
 * 消费和失败计数使用带状态条件的单条 UPDATE，保证同一个挑战不能被并发请求重复消费。</p>
 */
@ApplicationScoped
public class MfaChallengeRepository {
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(10);
    private static final int DEFAULT_MAX_ATTEMPTS = 5;
    private static final String ACTIVE_FILTER = "user_id = ? AND client_id = ? AND purpose = ? AND ((session_id = ?) OR (session_id IS NULL AND ? IS NULL)) AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP";
    @Inject DataSource dataSource;

    /** 创建短期挑战；只返回 ID 和状态元数据，不返回任何认证秘密。 */
    public Challenge create(long userId, Purpose purpose, String clientId, String sessionId, String contextHash, Instant expiresAt) {
        requireUser(userId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedClientId = normalizeClientId(clientId);
        String checkedSessionId = normalizeSessionId(sessionId);
        String checkedContextHash = normalizeContextHash(contextHash);
        Instant checkedExpiry = requireExpiry(expiresAt);
        String id = UUID.randomUUID().toString();
        String sql = "INSERT INTO sys_auth_challenge(id, user_id, purpose, client_id, session_id, context_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setString(1, id);
            p.setLong(2, userId);
            p.setString(3, checkedPurpose.value());
            p.setString(4, checkedClientId);
            setNullableString(p, 5, checkedSessionId);
            setNullableString(p, 6, checkedContextHash);
            p.setTimestamp(7, Timestamp.from(checkedExpiry));
            p.executeUpdate();
            return new Challenge(id, userId, checkedPurpose, checkedClientId, checkedSessionId, checkedExpiry, 0, null);
        } catch (Exception e) {
            throw new IllegalStateException("Could not create MFA challenge", e);
        }
    }

    /** 按主体、客户端、用途和会话读取仍可用的挑战；返回值不含上下文摘要。 */
    public List<Challenge> findActive(long userId, String clientId, Purpose purpose, String sessionId) {
        return queryActive(null, userId, clientId, purpose, sessionId);
    }

    /** 按不透明 ID 和绑定条件读取单个仍可用的挑战。 */
    public Optional<Challenge> findActive(String challengeId, long userId, String clientId, Purpose purpose, String sessionId) {
        return queryActive(challengeId, userId, clientId, purpose, sessionId).stream().findFirst();
    }

    private List<Challenge> queryActive(String challengeId, long userId, String clientId, Purpose purpose, String sessionId) {
        requireUser(userId);
        String checkedClientId = normalizeClientId(clientId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedSessionId = normalizeSessionId(sessionId);
        StringBuilder sql = new StringBuilder("SELECT id, user_id, purpose, client_id, session_id, expires_at, attempt_count, consumed_at FROM sys_auth_challenge WHERE ");
        if (challengeId != null) sql.append("id = ? AND ");
        sql.append(ACTIVE_FILTER).append(" ORDER BY created_at DESC");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql.toString())) {
            int index = 1;
            if (challengeId != null) p.setString(index++, normalizeChallengeId(challengeId));
            p.setLong(index++, userId);
            p.setString(index++, checkedClientId);
            p.setString(index++, checkedPurpose.value());
            setNullableString(p, index++, checkedSessionId);
            setNullableString(p, index, checkedSessionId);
            try (var rs = p.executeQuery()) {
                var result = new ArrayList<Challenge>();
                while (rs.next()) result.add(read(rs));
                return result;
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not read MFA challenge", e);
        }
    }

    /** 原子消费挑战；过期、重复消费、绑定不匹配或已达到失败上限都会失败。 */
    public boolean consume(String challengeId, long userId, String clientId, Purpose purpose, String sessionId) {
        return updateState(challengeId, userId, clientId, purpose, sessionId,
                "consumed_at = CURRENT_TIMESTAMP", "attempt_count < ?", DEFAULT_MAX_ATTEMPTS);
    }

    /** 原子增加失败次数；达到上限后后续请求不会再修改挑战状态。 */
    public boolean recordFailure(String challengeId, long userId, String clientId, Purpose purpose, String sessionId) {
        return updateState(challengeId, userId, clientId, purpose, sessionId,
                "attempt_count = attempt_count + 1", "attempt_count < ?", DEFAULT_MAX_ATTEMPTS);
    }

    private boolean updateState(String challengeId, long userId, String clientId, Purpose purpose, String sessionId, String assignment, String extraCondition, int extraValue) {
        requireUser(userId);
        String checkedId = normalizeChallengeId(challengeId);
        String checkedClientId = normalizeClientId(clientId);
        Purpose checkedPurpose = requirePurpose(purpose);
        String checkedSessionId = normalizeSessionId(sessionId);
        String sql = "UPDATE sys_auth_challenge SET " + assignment + " WHERE id = ? AND " + ACTIVE_FILTER + " AND " + extraCondition;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            int index = 1;
            p.setString(index++, checkedId);
            p.setLong(index++, userId);
            p.setString(index++, checkedClientId);
            p.setString(index++, checkedPurpose.value());
            setNullableString(p, index++, checkedSessionId);
            setNullableString(p, index++, checkedSessionId);
            p.setInt(index, extraValue);
            return p.executeUpdate() == 1;
        } catch (Exception e) {
            throw new IllegalStateException("Could not update MFA challenge", e);
        }
    }

    private static Challenge read(java.sql.ResultSet rs) throws Exception {
        Timestamp expiresAt = rs.getTimestamp("expires_at");
        Timestamp consumedAt = rs.getTimestamp("consumed_at");
        return new Challenge(rs.getString("id"), rs.getLong("user_id"), Purpose.from(rs.getString("purpose")),
                rs.getString("client_id"), rs.getString("session_id"), expiresAt == null ? null : expiresAt.toInstant(),
                rs.getInt("attempt_count"), consumedAt == null ? null : consumedAt.toInstant());
    }

    private static Instant requireExpiry(Instant value) {
        if (value == null) throw new IllegalArgumentException("expiresAt is required");
        Instant now = Instant.now();
        if (!value.isAfter(now) || value.isAfter(now.plus(MAX_LIFETIME))) throw new IllegalArgumentException("expiresAt must be within ten minutes");
        return value;
    }

    private static Purpose requirePurpose(Purpose value) { if (value == null) throw new IllegalArgumentException("purpose is required"); return value; }
    private static void requireUser(long value) { if (value <= 0) throw new IllegalArgumentException("userId must be positive"); }

    private static String normalizeChallengeId(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("challengeId is required");
        String normalized = value.trim();
        try { return UUID.fromString(normalized).toString(); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("challengeId must be a UUID"); }
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

    private static void setNullableString(java.sql.PreparedStatement p, int index, String value) throws Exception {
        if (value == null) p.setNull(index, Types.VARCHAR); else p.setString(index, value);
    }

    public enum Purpose {
        LOGIN("LOGIN"), STEP_UP("STEP_UP"), ENROLL("ENROLL"), RECOVERY("RECOVERY");

        private final String value;
        Purpose(String value) { this.value = value; }
        public String value() { return value; }
        private static Purpose from(String value) {
            for (Purpose purpose : values()) if (purpose.value.equals(value)) return purpose;
            throw new IllegalStateException("Unknown MFA challenge purpose");
        }
    }

    public record Challenge(String id, long userId, Purpose purpose, String clientId, String sessionId,
                            Instant expiresAt, int attemptCount, Instant consumedAt) {}
}
