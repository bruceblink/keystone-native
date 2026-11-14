package app.keystone.job;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.time.Instant;
import java.util.List;

/** 使用 ORM 管理计划任务，数据库结构由 Flyway 管理。 */
@ApplicationScoped
public class JobRepository implements PanacheRepositoryBase<JobEntity, java.util.UUID> {
    @jakarta.inject.Inject AuthorizationService authorization;

    @Transactional
    public List<Job> list() {
        return find("order by id").list().stream().map(JobEntity::toModel).toList();
    }

    /** 按主体范围查询任务；SELF 只读取由该主体创建的任务。 */
    @Transactional
    public List<Job> list(AuthorizationContext context) {
        authorization.require(context, "job:read", "job");
        var query = context.allScope() ? find("order by id")
                : find("createdBy = ?1 order by id", context.subjectId());
        return query.list().stream().map(JobEntity::toModel).toList();
    }

    /** 返回所有者创建的任务主键，供任务日志查询复用相同范围。 */
    List<java.util.UUID> idsForOwner(String ownerId) {
        return find("createdBy", ownerId).list().stream().map(JobEntity::idValue).toList();
    }

    /** 调度器只允许使用固定系统主体读取待执行任务，避免请求主体进入后台回调。 */
    @Transactional
    public List<Job> enabled(AuthorizationContext context) {
        authorization.require(context, "job:read", "job");
        return find("enabled = true order by id").list().stream().map(JobEntity::toModel).toList();
    }

    @Transactional
    public Job create(AuthorizationContext context, String code, String name, String group, String invokeTarget, String jobParams,
                      String cron, Boolean concurrent, Boolean enabled, String remark) {
        authorization.require(context, "job:create", "job", context.subjectId());
        require(code, "code");
        require(name, "name");
        require(cron, "cron");
        require(invokeTarget, "invokeTarget");
        try {
            var job = new JobEntity(code.trim(), name.trim(),
                    group == null || group.isBlank() ? "DEFAULT" : group.trim(),
                    invokeTarget.trim(), jobParams, cron.trim(),
                    concurrent == null || concurrent, enabled == null || enabled, remark, context.subjectId());
            persistAndFlush(job);
            return job.toModel();
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("job code already exists", e);
            throw new IllegalStateException("Could not create job", e);
        }
    }

    @Transactional
    public Job update(AuthorizationContext context, String id, String name, String group, String invokeTarget, String jobParams,
                      String cron, Boolean concurrent, Boolean enabled, String remark) {
        JobEntity job = findFor(context, "job:update", id, true);
        if (job == null) throw new java.util.NoSuchElementException("job not found");
        job.update(name, group, invokeTarget, jobParams, cron, concurrent, enabled, remark);
        return job.toModel();
    }

    /** 运行状态写入失败不改变任务执行结果。 */
    @Transactional
    public void markRun(String id, String status) {
        try {
            JobEntity job = find("id = ?1", parse(id)).firstResult();
            if (job != null) job.markRun(status, Instant.now());
        } catch (RuntimeException ignored) {
            // 运行状态只用于诊断，持久化异常不能改变调度结果。
        }
    }

    @Transactional
    public void delete(AuthorizationContext context, String id) {
        JobEntity job = findFor(context, "job:delete", id, true);
        if (job == null) throw new java.util.NoSuchElementException("job not found");
        delete(job);
    }

    /** 在同一事务内锁定并删除全部任务；缺失或越界时不允许部分删除。 */
    @Transactional
    public List<Job> deleteAll(AuthorizationContext context, List<String> ids) {
        authorization.require(context, "job:delete", "job");
        List<java.util.UUID> uniqueIds = parseIds(ids);
        var query = context.allScope()
                ? find("id in ?1", uniqueIds)
                : find("id in ?1 and createdBy = ?2", uniqueIds, context.subjectId());
        List<JobEntity> entities = query.withLock(LockModeType.PESSIMISTIC_WRITE).list();
        if (entities.size() != uniqueIds.size()) throw new java.util.NoSuchElementException("job not found");
        List<Job> deleted = entities.stream().map(JobEntity::toModel).toList();
        entities.forEach(this::delete);
        return deleted;
    }

    @Transactional
    public Job findById(AuthorizationContext context, String id) {
        return findById(context, id, "job:read");
    }

    @Transactional
    public Job findById(AuthorizationContext context, String id, String permission) {
        JobEntity job = findFor(context, permission, id, false);
        if (job == null) throw new java.util.NoSuchElementException("job not found");
        return job.toModel();
    }

    /** 预读并锁定批量目标的范围；任何一个目标缺失或越界都会整体失败。 */
    @Transactional
    public List<Job> findAll(AuthorizationContext context, List<String> ids, String permission) {
        authorization.require(context, permission, "job");
        List<java.util.UUID> uniqueIds = parseIds(ids);
        var query = context.allScope()
                ? find("id in ?1", uniqueIds)
                : find("id in ?1 and createdBy = ?2", uniqueIds, context.subjectId());
        List<JobEntity> entities = query.withLock(LockModeType.PESSIMISTIC_WRITE).list();
        if (entities.size() != uniqueIds.size()) throw new java.util.NoSuchElementException("job not found");
        return entities.stream().map(JobEntity::toModel).toList();
    }

    private JobEntity findFor(AuthorizationContext context, String permission, String id, boolean lock) {
        authorization.require(context, permission, "job");
        var query = context.allScope()
                ? find("id = ?1", parse(id))
                : find("id = ?1 and createdBy = ?2", parse(id), context.subjectId());
        return (lock ? query.withLock(LockModeType.PESSIMISTIC_WRITE) : query).firstResult();
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static java.util.UUID parse(String value) {
        return app.keystone.identity.UuidValues.parse(value);
    }

    private static boolean isConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("unique")) return true;
        }
        return false;
    }

    /** 规范化批量主键并去重，保持重复请求的幂等删除语义。 */
    private static List<java.util.UUID> parseIds(List<String> ids) {
        if (ids == null || ids.isEmpty()) throw new IllegalArgumentException("ids is required");
        var unique = new java.util.LinkedHashSet<java.util.UUID>();
        for (String id : ids) unique.add(app.keystone.identity.UuidValues.parse(id));
        if (unique.isEmpty()) throw new IllegalArgumentException("ids is required");
        return List.copyOf(unique);
    }
}
