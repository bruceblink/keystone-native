package app.keystone.audit;

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

/** ORM 映射操作日志；数据库表结构由 Flyway 管理，实体不负责创建表。 */
@Entity
@Table(name = "sys_operation_log")
public class OperationLogEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "actor_username", nullable = false, length = 64)
    private String actorUsername;

    @Column(nullable = false, length = 32)
    private String action;

    @Column(nullable = false, length = 64)
    private String resource;

    @Column(name = "resource_id", length = 64)
    private String resourceId;

    @Column(length = 1000)
    private String detail;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected OperationLogEntity() {
    }

    OperationLogEntity(String actorUsername, String action, String resource, String resourceId, String detail) {
        this.id = java.util.UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.actorUsername = actorUsername;
        this.action = action;
        this.resource = resource;
        this.resourceId = resourceId;
        this.detail = detail;
    }

    OperationLog toModel() {
        return new OperationLog(id == null ? null : id.toString(), actorUsername, action, resource, resourceId, detail, createdAt);
    }
}
