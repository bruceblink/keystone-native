package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import app.keystone.identity.UuidBinaryConverter;

import java.time.Instant;

/** 映射 API Key 主记录；密钥明文只在签发结果中出现，不写入实体。 */
@Entity
@Table(name = "sys_api_key")
public class ApiKeyEntity {
    @Id
    @Column(nullable = false, length = 36)
    private String id;

    @Column(name = "user_id", nullable = false)
    @Convert(converter = UuidBinaryConverter.class)
    private String userId;

    @Column(name = "subject_id", length = 36)
    private String subjectId;

    @Column(name = "created_by")
    @Convert(converter = UuidBinaryConverter.class)
    private String createdBy;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "key_prefix", nullable = false, unique = true, length = 24)
    private String keyPrefix;

    @Column(name = "key_hash", nullable = false, unique = true, length = 64)
    private String keyHash;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "last_used_ip", length = 64)
    private String lastUsedIp;

    @Column(name = "rotated_to", length = 36)
    private String rotatedTo;

    @Column(name = "revoked_reason", length = 255)
    private String revokedReason;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected ApiKeyEntity() {
    }

    ApiKeyEntity(String id, String userId, String subjectId, String createdBy, String name,
                 String keyPrefix, String keyHash, String scopes, Instant expiresAt) {
        this.id = id;
        this.userId = userId;
        this.subjectId = subjectId;
        this.createdBy = createdBy;
        this.name = name;
        this.keyPrefix = keyPrefix;
        this.keyHash = keyHash;
        this.scopes = scopes;
        this.expiresAt = expiresAt;
    }

    String id() {
        return id;
    }

    String userId() {
        return userId;
    }

    String subjectId() {
        return subjectId;
    }

    String name() {
        return name;
    }

    String keyPrefix() {
        return keyPrefix;
    }

    String scopes() {
        return scopes;
    }

    Instant expiresAt() {
        return expiresAt;
    }

    Instant revokedAt() {
        return revokedAt;
    }

    Instant lastUsedAt() {
        return lastUsedAt;
    }

    Instant createdAt() {
        return createdAt;
    }

    void revoke(Instant at, String reason, String replacementId) {
        if (revokedAt == null) revokedAt = at;
        if (revokedReason == null) revokedReason = reason;
        if (replacementId != null) rotatedTo = replacementId;
    }
}
