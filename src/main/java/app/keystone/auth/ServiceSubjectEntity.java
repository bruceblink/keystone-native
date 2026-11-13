package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** 映射 API Key 使用的服务主体；服务主体表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_service_subject")
public class ServiceSubjectEntity {
    @Id
    @Column(nullable = false, length = 36)
    private String id;

    @Column(nullable = false, length = 128)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "owner_user_id")
    private Long ownerUserId;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected ServiceSubjectEntity() {
    }

    ServiceSubjectEntity(String id, String code, String name, Long ownerUserId) {
        this.id = id;
        this.code = code;
        this.name = name;
        this.ownerUserId = ownerUserId;
        this.enabled = true;
    }

    String id() {
        return id;
    }

    boolean enabled() {
        return enabled;
    }
}
