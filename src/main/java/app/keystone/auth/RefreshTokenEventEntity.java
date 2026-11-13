package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** 保存刷新令牌安全事件，事件写入失败会回滚所属认证事务。 */
@Entity
@Table(name = "sys_refresh_token_event")
public class RefreshTokenEventEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token_id")
    private Long tokenId;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "refresh_family_id", length = 36)
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

    RefreshTokenEventEntity(Long tokenId, long userId, String refreshFamilyId, String eventType,
                            String clientId, String detail) {
        this.tokenId = tokenId;
        this.userId = userId;
        this.refreshFamilyId = refreshFamilyId;
        this.eventType = eventType;
        this.clientId = clientId;
        this.detail = detail;
    }
}
