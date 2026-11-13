package app.keystone.job;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** 映射计划任务；数据库表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_job")
public class JobEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "job_group", nullable = false, length = 64)
    private String jobGroup;

    @Column(name = "invoke_target", nullable = false, length = 255)
    private String invokeTarget;

    @Column(name = "job_params", columnDefinition = "TEXT")
    private String jobParams;

    @Column(nullable = false, length = 128)
    private String cron;

    @Column(nullable = false)
    private boolean concurrent;

    @Column(nullable = false)
    private boolean enabled;

    @Column(length = 255)
    private String remark;

    @Column(name = "last_status", length = 16)
    private String lastStatus;

    @Column(name = "last_run_at")
    private Instant lastRunAt;

    protected JobEntity() {
    }

    JobEntity(String code, String name, String jobGroup, String invokeTarget, String jobParams,
              String cron, boolean concurrent, boolean enabled, String remark) {
        this.code = code;
        this.name = name;
        this.jobGroup = jobGroup;
        this.invokeTarget = invokeTarget;
        this.jobParams = jobParams;
        this.cron = cron;
        this.concurrent = concurrent;
        this.enabled = enabled;
        this.remark = remark;
    }

    void update(String newName, String newGroup, String newInvokeTarget, String newJobParams,
                String newCron, Boolean newConcurrent, Boolean newEnabled, String newRemark) {
        if (newName != null && !newName.isBlank()) name = newName.trim();
        if (newGroup != null && !newGroup.isBlank()) jobGroup = newGroup.trim();
        if (newInvokeTarget != null && !newInvokeTarget.isBlank()) invokeTarget = newInvokeTarget.trim();
        if (newJobParams != null) jobParams = newJobParams;
        if (newCron != null && !newCron.isBlank()) cron = newCron.trim();
        if (newConcurrent != null) concurrent = newConcurrent;
        if (newEnabled != null) enabled = newEnabled;
        if (newRemark != null) remark = newRemark;
    }

    void markRun(String status, Instant at) {
        lastStatus = status;
        lastRunAt = at;
    }

    Job toModel() {
        return new Job(id, code, name, jobGroup, invokeTarget, jobParams, cron, concurrent,
                enabled, remark, lastStatus, lastRunAt);
    }
}
