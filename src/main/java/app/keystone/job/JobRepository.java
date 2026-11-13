package app.keystone.job;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.time.Instant;
import java.util.List;

/** 使用 ORM 管理计划任务，数据库结构由 Flyway 管理。 */
@ApplicationScoped
public class JobRepository implements PanacheRepository<JobEntity> {
    @Transactional
    public List<Job> list() {
        return find("order by id").list().stream().map(JobEntity::toModel).toList();
    }

    @Transactional
    public List<Job> enabled() {
        return find("enabled = true order by id").list().stream().map(JobEntity::toModel).toList();
    }

    @Transactional
    public Job create(String code, String name, String group, String invokeTarget, String jobParams,
                      String cron, Boolean concurrent, Boolean enabled, String remark) {
        require(code, "code");
        require(name, "name");
        require(cron, "cron");
        require(invokeTarget, "invokeTarget");
        try {
            var job = new JobEntity(code.trim(), name.trim(),
                    group == null || group.isBlank() ? "DEFAULT" : group.trim(),
                    invokeTarget.trim(), jobParams, cron.trim(),
                    concurrent == null || concurrent, enabled == null || enabled, remark);
            persistAndFlush(job);
            return job.toModel();
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("job code already exists", e);
            throw new IllegalStateException("Could not create job", e);
        }
    }

    @Transactional
    public Job update(long id, String name, String group, String invokeTarget, String jobParams,
                      String cron, Boolean concurrent, Boolean enabled, String remark) {
        JobEntity job = find("id = ?1", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (job == null) throw new java.util.NoSuchElementException("job not found");
        job.update(name, group, invokeTarget, jobParams, cron, concurrent, enabled, remark);
        return job.toModel();
    }

    /** 运行状态写入失败不改变任务执行结果。 */
    @Transactional
    public void markRun(long id, String status) {
        try {
            JobEntity job = find("id = ?1", id).firstResult();
            if (job != null) job.markRun(status, Instant.now());
        } catch (RuntimeException ignored) {
            // 运行状态只用于诊断，持久化异常不能改变调度结果。
        }
    }

    @Transactional
    public void delete(long id) {
        JobEntity job = find("id = ?1", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (job == null) throw new java.util.NoSuchElementException("job not found");
        delete(job);
    }

    @Transactional
    public Job findById(long id) {
        JobEntity job = find("id = ?1", id).firstResult();
        if (job == null) throw new java.util.NoSuchElementException("job not found");
        return job.toModel();
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static boolean isConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("unique")) return true;
        }
        return false;
    }
}
