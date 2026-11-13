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

/** 映射 API Key 使用的服务主体；服务主体表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_service_subject")
public class ServiceSubjectEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 128)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "owner_user_id")
    @Convert(converter = UuidBinaryConverter.class)
    private String ownerUserId;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected ServiceSubjectEntity() {
    }

    ServiceSubjectEntity(String id, String code, String name, String ownerUserId) {
        this.id = app.keystone.identity.UuidValues.parse(id);
        this.code = code;
        this.name = name;
        this.ownerUserId = ownerUserId;
        this.enabled = true;
    }

    String id() {
        return id == null ? null : id.toString();
    }

    boolean enabled() {
        return enabled;
    }
}
