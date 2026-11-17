package app.keystone.notification;

import app.keystone.identity.UuidBinaryConverter;
import app.keystone.identity.UuidValues;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** 映射收件人专属的站内通知；数据库迁移负责创建表和索引。 */
@Entity
@Table(name = "sys_notification")
class NotificationEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "recipient_user_id", nullable = false, columnDefinition = "BINARY(16)", length = 16)
    @Convert(converter = UuidBinaryConverter.class)
    private String recipientUserId;

    @Column(nullable = false, length = 64)
    private String type;

    @Column(nullable = false, length = 128)
    private String title;

    @Column(nullable = false, length = 512)
    private String content;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "read_at")
    private Instant readAt;

    protected NotificationEntity() {
    }

    NotificationEntity(String id, String recipientUserId, String type, String title, String content) {
        this.id = UuidValues.parse(id);
        this.recipientUserId = UuidValues.requireCanonical(recipientUserId);
        this.type = type;
        this.title = title;
        this.content = content;
    }

    String id() {
        return id == null ? null : id.toString();
    }

    String type() {
        return type;
    }

    String title() {
        return title;
    }

    String content() {
        return content;
    }

    Instant createdAt() {
        return createdAt;
    }

    Instant readAt() {
        return readAt;
    }

    /** 首次打开详情时写入已读时间，重复请求保持原时间。 */
    void markRead(Instant at) {
        if (readAt == null) readAt = at;
    }
}
