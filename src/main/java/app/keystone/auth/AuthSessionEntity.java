package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import app.keystone.identity.UuidBinaryConverter;

import java.time.Instant;

/** 映射独立会话状态；刷新令牌只保存轮换明细，表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_auth_session")
public class AuthSessionEntity {
    @Id
    @Column(nullable = false, length = 36)
    private String id;

    @Column(name = "user_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String userId;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @Column(name = "approved_scope", columnDefinition = "TEXT")
    private String approvedScope;

    @Column(name = "refresh_family_id", nullable = false, length = 36)
    private String refreshFamilyId;

    @Column(name = "refresh_expires_at", nullable = false)
    private Instant refreshExpiresAt;

    @Column(name = "idle_expires_at", nullable = false)
    private Instant idleExpiresAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "mfa_verified_at")
    private Instant mfaVerifiedAt;

    @Column(name = "mfa_assurance", length = 32)
    private String mfaAssurance;

    @Column(name = "mfa_amr", length = 128)
    private String mfaAmr;

    protected AuthSessionEntity() {
    }

    AuthSessionEntity(String id, String userId, String clientId, String approvedScope,
                      String refreshFamilyId, Instant refreshExpiresAt, Instant idleExpiresAt, Instant lastSeenAt) {
        this.id = id;
        this.userId = userId;
        this.clientId = clientId;
        this.approvedScope = approvedScope;
        this.refreshFamilyId = refreshFamilyId;
        this.refreshExpiresAt = refreshExpiresAt;
        this.idleExpiresAt = idleExpiresAt;
        this.lastSeenAt = lastSeenAt;
    }

    String id() { return id; }
    String userId() { return userId; }
    String clientId() { return clientId; }
    String approvedScope() { return approvedScope; }
    String refreshFamilyId() { return refreshFamilyId; }
    Instant refreshExpiresAt() { return refreshExpiresAt; }
    Instant idleExpiresAt() { return idleExpiresAt; }
    Instant lastSeenAt() { return lastSeenAt; }
    Instant revokedAt() { return revokedAt; }
    Instant createdAt() { return createdAt; }
    Instant mfaVerifiedAt() { return mfaVerifiedAt; }
    String mfaAssurance() { return mfaAssurance; }

    boolean activeAt(Instant now) {
        return revokedAt == null && refreshExpiresAt != null && refreshExpiresAt.isAfter(now)
                && idleExpiresAt != null && idleExpiresAt.isAfter(now);
    }

    void revoke(Instant at) {
        if (revokedAt == null) revokedAt = at;
    }

    void touch(Instant now, Instant nextIdle) {
        idleExpiresAt = nextIdle;
        lastSeenAt = now;
    }

    void markMfaVerified(Instant now, String assurance, String amr) {
        mfaVerifiedAt = now;
        mfaAssurance = assurance;
        mfaAmr = amr;
    }
}
