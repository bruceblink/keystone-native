package app.keystone.job;

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

/** 映射计划任务执行记录；数据库表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_job_log")
public class JobLogEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "job_id", columnDefinition = "BINARY(16)")
    private UUID jobId;

    @Column(name = "job_code", nullable = false, length = 64)
    private String jobCode;

    @Column(name = "job_name", nullable = false, length = 128)
    private String jobName;

    @Column(name = "job_group", nullable = false, length = 64)
    private String jobGroup;

    @Column(name = "invoke_target", nullable = false, length = 255)
    private String invokeTarget;

    @Column(name = "job_params", columnDefinition = "TEXT")
    private String jobParams;

    @Column(nullable = false, length = 128)
    private String cron;

    @Column(name = "trigger_type", nullable = false, columnDefinition = "TINYINT")
    private int triggerType;

    @Column(nullable = false, columnDefinition = "TINYINT")
    private int status;

    @Column(name = "job_message", nullable = false, length = 500)
    private String jobMessage;

    @Column(name = "exception_info", columnDefinition = "TEXT")
    private String exceptionInfo;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt;

    @Column(name = "finished_at")
    private Instant finishedAt;

    @Column(name = "duration_ms")
    private Long durationMs;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected JobLogEntity() {
    }

    JobLogEntity(JobLog log) {
        // 每次任务执行记录使用 UUIDv7，保持日志主键的时间顺序和统一身份格式。
        id = app.keystone.identity.UuidValues.v7Uuid();
        jobId = log.jobId() == null ? null : UUID.fromString(app.keystone.identity.UuidValues.requireCanonical(log.jobId()));
        jobCode = log.jobCode();
        jobName = log.jobName();
        jobGroup = log.jobGroup();
        invokeTarget = log.invokeTarget();
        jobParams = log.jobParams();
        cron = log.cron();
        triggerType = log.triggerType();
        status = log.status();
        jobMessage = log.jobMessage();
        exceptionInfo = log.exceptionInfo();
        startedAt = log.startedAt();
        finishedAt = log.finishedAt();
        durationMs = log.durationMs();
    }

    JobLog toModel() {
        return new JobLog(id == null ? null : id.toString(), jobId == null ? null : jobId.toString(), jobCode, jobName, jobGroup, invokeTarget, jobParams, cron,
                triggerType, status, jobMessage, exceptionInfo, startedAt, finishedAt, durationMs, createdAt);
    }
}
