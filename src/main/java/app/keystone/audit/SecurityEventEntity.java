package app.keystone.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** ORM 映射安全边界事件；表结构仍由 Flyway 迁移管理。 */
@Entity
@Table(name = "sys_security_event")
public class SecurityEventEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 32)
    private String eventType;

    @Column(length = 128)
    private String actor;

    @Column(name = "credential_type", length = 32)
    private String credentialType;

    @Column(name = "credential_id", length = 128)
    private String credentialId;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(length = 128)
    private String resource;

    @Column(length = 128)
    private String action;

    @Column(nullable = false, length = 32)
    private String outcome;

    @Column(length = 255)
    private String detail;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected SecurityEventEntity() {
    }

    SecurityEventEntity(String eventType, String actor, String credentialType, String credentialId,
                        String sourceIp, String resource, String action, String outcome, String detail) {
        this.eventType = eventType;
        this.actor = actor;
        this.credentialType = credentialType;
        this.credentialId = credentialId;
        this.sourceIp = sourceIp;
        this.resource = resource;
        this.action = action;
        this.outcome = outcome;
        this.detail = detail;
    }

    public Long getId() {
        return id;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
