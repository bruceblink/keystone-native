package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import app.keystone.identity.UuidBinaryConverter;

import java.time.Instant;

/** 映射用户 TOTP 状态和密文；实体不解密也不返回明文密钥。 */
@Entity
@Table(name = "sys_user_mfa")
public class UserMfaEntity {
    @Id
    @Column(nullable = false, length = 36)
    private String id;

    @Column(name = "user_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String userId;

    @Column(name = "mfa_type", nullable = false, length = 16)
    private String mfaType;

    @Lob
    @Column(name = "secret_ciphertext", nullable = false)
    private byte[] secretCiphertext;

    @Column(name = "secret_nonce", nullable = false, columnDefinition = "VARBINARY(12)", length = 12)
    private byte[] secretNonce;

    @Column(name = "key_version", nullable = false)
    private int keyVersion;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "enrolled_at")
    private Instant enrolledAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "failed_attempt_count", nullable = false)
    private int failedAttemptCount;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "last_accepted_step")
    private Long lastAcceptedStep;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected UserMfaEntity() {
    }

    UserMfaEntity(String id, String userId, String mfaType, byte[] secretCiphertext, byte[] secretNonce,
                  int keyVersion) {
        this.id = id;
        this.userId = userId;
        this.mfaType = mfaType;
        this.secretCiphertext = secretCiphertext;
        this.secretNonce = secretNonce;
        this.keyVersion = keyVersion;
    }

    String id() {
        return id;
    }

    String userId() {
        return userId;
    }

    String mfaType() {
        return mfaType;
    }

    byte[] secretCiphertext() {
        return secretCiphertext;
    }

    byte[] secretNonce() {
        return secretNonce;
    }

    int keyVersion() {
        return keyVersion;
    }

    boolean enabled() {
        return enabled;
    }

    Instant enrolledAt() {
        return enrolledAt;
    }

    Instant lastUsedAt() {
        return lastUsedAt;
    }

    int failedAttemptCount() {
        return failedAttemptCount;
    }

    Instant lockedUntil() {
        return lockedUntil;
    }

    Long lastAcceptedStep() {
        return lastAcceptedStep;
    }

    Instant createdAt() {
        return createdAt;
    }

    Instant updatedAt() {
        return updatedAt;
    }

    boolean canAcceptStep(long candidateStep, Instant now, boolean enrollmentVerification) {
        return (enabled || enrollmentVerification)
                && (lockedUntil == null || !lockedUntil.isAfter(now))
                && (lastAcceptedStep == null || lastAcceptedStep < candidateStep);
    }

    /** 记录成功的 TOTP 时间步并清除临时锁定状态。 */
    boolean acceptStep(long candidateStep, Instant now, boolean enrollmentVerification) {
        if (!canAcceptStep(candidateStep, now, enrollmentVerification)) return false;
        lastAcceptedStep = candidateStep;
        lastUsedAt = now;
        failedAttemptCount = 0;
        lockedUntil = null;
        return true;
    }

    /** 记录一次 MFA 校验失败；调用方必须先在事务中锁定实体。 */
    boolean recordFailure(Instant now, int maxFailures, long lockSeconds) {
        if (lockedUntil != null && lockedUntil.isAfter(now)) return false;
        failedAttemptCount++;
        if (failedAttemptCount >= maxFailures) lockedUntil = now.plusSeconds(lockSeconds);
        return true;
    }

    void enable(Instant at) {
        enabled = true;
        enrolledAt = at;
        failedAttemptCount = 0;
        lockedUntil = null;
    }

    void replacePendingSecret(byte[] newCiphertext, byte[] newNonce, int newKeyVersion) {
        secretCiphertext = newCiphertext;
        secretNonce = newNonce;
        keyVersion = newKeyVersion;
        enabled = false;
        enrolledAt = null;
        lastUsedAt = null;
        failedAttemptCount = 0;
        lockedUntil = null;
        lastAcceptedStep = null;
    }
}
