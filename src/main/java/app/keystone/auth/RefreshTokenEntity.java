package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import app.keystone.identity.UuidBinaryConverter;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** 映射刷新令牌轮换明细；数据库只保存令牌摘要，不保存明文令牌。 */
@Entity
@Table(name = "sys_refresh_token")
public class RefreshTokenEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "user_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String userId;

    @Column(name = "session_id", columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String sessionId;

    @Column(name = "refresh_family_id", columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String refreshFamilyId;

    @Column(name = "client_id", length = 128)
    private String clientId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "idle_expires_at")
    private Instant idleExpiresAt;

    @Column(name = "access_expires_at")
    private Instant accessExpiresAt;

    @Column(name = "access_token_id", columnDefinition = "BINARY(16)", unique = true, length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String accessTokenId;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "reused_at")
    private Instant reusedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected RefreshTokenEntity() {
    }

    RefreshTokenEntity(String userId, String sessionId, String refreshFamilyId, String clientId,
                       String tokenHash, Instant expiresAt, Instant idleExpiresAt,
                       Instant accessExpiresAt, String accessTokenId) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.userId = userId;
        this.sessionId = sessionId;
        this.refreshFamilyId = refreshFamilyId;
        this.clientId = clientId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.idleExpiresAt = idleExpiresAt;
        this.accessExpiresAt = accessExpiresAt;
        this.accessTokenId = accessTokenId;
    }

    String id() { return id == null ? null : id.toString(); }
    String userId() { return userId; }
    String sessionId() { return sessionId; }
    String refreshFamilyId() { return refreshFamilyId; }
    String clientId() { return clientId; }
    Instant expiresAt() { return expiresAt; }
    Instant idleExpiresAt() { return idleExpiresAt; }
    Instant accessExpiresAt() { return accessExpiresAt; }
    String accessTokenId() { return accessTokenId; }
    Instant revokedAt() { return revokedAt; }
    Instant reusedAt() { return reusedAt; }

    boolean activeAt(Instant now) {
        return revokedAt == null && expiresAt != null && expiresAt.isAfter(now)
                && idleExpiresAt != null && idleExpiresAt.isAfter(now);
    }

    void revoke(Instant at) {
        if (revokedAt == null) revokedAt = at;
    }

    void markReused(Instant at) {
        if (reusedAt == null) reusedAt = at;
        revoke(at);
    }
}
