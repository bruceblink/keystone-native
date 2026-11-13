package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** 保存刷新令牌安全事件，事件写入失败会回滚所属认证事务。 */
@Entity
@Table(name = "sys_refresh_token_event")
public class RefreshTokenEventEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "token_id", columnDefinition = "BINARY(16)")
    private UUID tokenId;

    @Column(name = "user_id", columnDefinition = "BINARY(16)", length = 16)
    @jakarta.persistence.Convert(converter = app.keystone.identity.UuidBinaryConverter.class)
    private String userId;

    @Column(name = "refresh_family_id", columnDefinition = "BINARY(16)", length = 16)
    @jakarta.persistence.Convert(converter = app.keystone.identity.UuidBinaryConverter.class)
    private String refreshFamilyId;

    @Column(name = "event_type", nullable = false, length = 32)
    private String eventType;

    @Column(name = "client_id", length = 128)
    private String clientId;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(length = 255)
    private String detail;

    protected RefreshTokenEventEntity() {
    }

    RefreshTokenEventEntity(String tokenId, String userId, String refreshFamilyId, String eventType,
                            String clientId, String detail) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.tokenId = tokenId == null ? null : app.keystone.identity.UuidValues.parse(tokenId);
        this.userId = userId;
        this.refreshFamilyId = refreshFamilyId;
        this.eventType = eventType;
        this.clientId = clientId;
        this.detail = detail;
    }
}
