package app.keystone.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;
import app.keystone.identity.UuidBinaryConverter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** ORM 映射安全边界事件；表结构仍由 Flyway 迁移管理。 */
@Entity
@Table(name = "sys_security_event")
public class SecurityEventEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "event_type", nullable = false, length = 32)
    private String eventType;

    @Column(length = 128)
    private String actor;

    @Column(name = "credential_type", length = 32)
    private String credentialType;

    @Column(name = "credential_id", length = 128)
    private String credentialId;

    @Convert(converter = UuidBinaryConverter.class)
    @Column(name = "session_id", columnDefinition = "BINARY(16)", length = 16)
    private String sessionId;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(length = 128)
    private String resource;

    @Column(length = 128)
    private String action;

    @Column(columnDefinition = "TEXT")
    private String scope;

    @Column(name = "request_id", length = 128)
    private String requestId;

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
        this(eventType, actor, credentialType, credentialId, sourceIp, resource, action, outcome,
                null, null, null, detail);
    }

    SecurityEventEntity(String eventType, String actor, String credentialType, String credentialId,
                        String sourceIp, String resource, String action, String outcome,
                        String sessionId, String scope, String requestId, String detail) {
        this.id = java.util.UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.eventType = eventType;
        this.actor = actor;
        this.credentialType = credentialType;
        this.credentialId = credentialId;
        this.sourceIp = sourceIp;
        this.resource = resource;
        this.action = action;
        this.outcome = outcome;
        this.detail = detail;
        this.sessionId = sessionId == null ? null : app.keystone.identity.UuidValues.requireCanonical(sessionId);
        this.scope = scope;
        this.requestId = requestId;
    }

    public String getId() {
        return id == null ? null : id.toString();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getEventType() {
        return eventType;
    }

    public String getActor() {
        return actor;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getRequestId() {
        return requestId;
    }
}
