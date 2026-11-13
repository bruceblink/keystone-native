package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** 映射一次性恢复码哈希和消费状态；数据库不保存恢复码明文。 */
@Entity
@Table(name = "sys_mfa_recovery_code")
public class MfaRecoveryCodeEntity {
    @Id
    @Column(nullable = false, length = 36)
    private String id;

    @Column(name = "user_id", nullable = false)
    private long userId;

    @Column(name = "batch_id", nullable = false, length = 36)
    private String batchId;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected MfaRecoveryCodeEntity() {
    }

    MfaRecoveryCodeEntity(String id, long userId, String batchId, String codeHash) {
        this.id = id;
        this.userId = userId;
        this.batchId = batchId;
        this.codeHash = codeHash;
    }

    String id() {
        return id;
    }

    long userId() {
        return userId;
    }

    String batchId() {
        return batchId;
    }

    String codeHash() {
        return codeHash;
    }

    Instant usedAt() {
        return usedAt;
    }

    Instant createdAt() {
        return createdAt;
    }

    /** 消费未使用的恢复码；调用方必须先在事务中锁定实体。 */
    boolean consume(Instant at) {
        if (usedAt != null) return false;
        usedAt = at;
        return true;
    }
}
