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

/** 映射一次性恢复码哈希和消费状态；数据库不保存恢复码明文。 */
@Entity
@Table(name = "sys_mfa_recovery_code")
public class MfaRecoveryCodeEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "user_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String userId;

    @Column(name = "batch_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String batchId;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected MfaRecoveryCodeEntity() {
    }

    MfaRecoveryCodeEntity(String id, String userId, String batchId, String codeHash) {
        this.id = app.keystone.identity.UuidValues.parse(id);
        this.userId = userId;
        this.batchId = batchId;
        this.codeHash = codeHash;
    }

    String id() {
        return id == null ? null : id.toString();
    }

    String userId() {
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
