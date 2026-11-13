package app.keystone.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** ORM 映射操作日志；数据库表结构由 Flyway 管理，实体不负责创建表。 */
@Entity
@Table(name = "sys_operation_log")
public class OperationLogEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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
        this.actorUsername = actorUsername;
        this.action = action;
        this.resource = resource;
        this.resourceId = resourceId;
        this.detail = detail;
    }

    OperationLog toModel() {
        return new OperationLog(id, actorUsername, action, resource, resourceId, detail, createdAt);
    }
}
