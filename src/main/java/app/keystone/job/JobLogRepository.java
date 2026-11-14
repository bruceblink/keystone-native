package app.keystone.job;

import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.util.List;

/** 使用 ORM 保存和分页查询计划任务执行记录。 */
@ApplicationScoped
public class JobLogRepository implements PanacheRepository<JobLogEntity> {
    @jakarta.inject.Inject JobRepository jobs;
    @Transactional
    public void save(JobLog log) {
        try {
            persist(new JobLogEntity(log));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not save job log", e);
        }
    }

    @Transactional
    public Page list(String jobId, int page, int size) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        PanacheQuery<JobLogEntity> query = jobId == null
                ? find("order by id desc")
                : find("jobId = ?1 order by id desc", app.keystone.identity.UuidValues.parse(jobId));
        long total = query.count();
        List<JobLog> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(JobLogEntity::toModel).toList();
        return new Page(items, safePage, safeSize, total);
    }

    /** SELF 主体只读取其创建任务的执行记录；旧任务没有所有者时不可见。 */
    @Transactional
    public Page listForOwner(String ownerId, int page, int size) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        List<java.util.UUID> jobIds = jobs.idsForOwner(ownerId);
        if (jobIds.isEmpty()) return new Page(List.of(), safePage, safeSize, 0);
        PanacheQuery<JobLogEntity> query = find("jobId in ?1 order by id desc", jobIds);
        long total = query.count();
        List<JobLog> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(JobLogEntity::toModel).toList();
        return new Page(items, safePage, safeSize, total);
    }

    public record Page(List<JobLog> items, int page, int size, long total) {
    }
}
