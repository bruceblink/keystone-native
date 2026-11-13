package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import app.keystone.identity.UuidBinaryConverter;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** 映射 MFA 认证请求的状态；上下文摘要只在实体内部保存，不返回给接口调用方。 */
@Entity
@Table(name = "sys_auth_challenge")
public class AuthChallengeEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "user_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String userId;

    @Column(nullable = false, length = 16)
    private String purpose;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @Column(name = "session_id", columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String sessionId;

    @Column(name = "context_hash", length = 64)
    private String contextHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected AuthChallengeEntity() {
    }

    AuthChallengeEntity(String id, String userId, String purpose, String clientId, String sessionId,
                        String contextHash, Instant expiresAt) {
        this.id = app.keystone.identity.UuidValues.parse(id);
        this.userId = userId;
        this.purpose = purpose;
        this.clientId = clientId;
        this.sessionId = sessionId;
        this.contextHash = contextHash;
        this.expiresAt = expiresAt;
    }

    String id() {
        return id == null ? null : id.toString();
    }

    String userId() {
        return userId;
    }

    String purpose() {
        return purpose;
    }

    String clientId() {
        return clientId;
    }

    String sessionId() {
        return sessionId;
    }

    String contextHash() {
        return contextHash;
    }

    Instant expiresAt() {
        return expiresAt;
    }

    int attemptCount() {
        return attemptCount;
    }

    Instant consumedAt() {
        return consumedAt;
    }

    Instant createdAt() {
        return createdAt;
    }

    boolean activeAt(Instant now, int maxAttempts) {
        return consumedAt == null && expiresAt != null && expiresAt.isAfter(now)
                && attemptCount < maxAttempts;
    }

    /** 消费已经在同一事务中锁定并复核的认证请求。 */
    boolean consume(Instant at, int maxAttempts) {
        if (!activeAt(at, maxAttempts)) return false;
        consumedAt = at;
        return true;
    }

    /** 增加失败次数；调用方必须先在事务中锁定实体。 */
    boolean recordFailure(Instant now, int maxAttempts) {
        if (!activeAt(now, maxAttempts)) return false;
        attemptCount++;
        return true;
    }
}
