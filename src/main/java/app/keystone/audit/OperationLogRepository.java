package app.keystone.audit;

import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import io.quarkus.panache.common.Sort;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.util.ArrayList;
import java.util.List;

/** 使用 Panache 管理操作日志，避免业务代码直接依赖 JDBC 和手写 SQL。 */
@ApplicationScoped
public class OperationLogRepository implements PanacheRepository<OperationLogEntity> {

    /** 审计记录失败不应阻断主业务，同时使用独立事务避免跟随调用方回滚。 */
    @Transactional(Transactional.TxType.REQUIRES_NEW)
    public void record(String actor, String action, String resource, String resourceId, String detail) {
        try {
            persistAndFlush(new OperationLogEntity(
                    actor == null || actor.isBlank() ? "system" : actor.trim(),
                    action,
                    resource,
                    resourceId,
                    detail));
        } catch (RuntimeException ignored) {
            // 审计写入失败只记录运行时日志，不能改变已接受的业务请求结果。
        }
    }

    public Page list(int page, int size) {
        return list(page, size, null, null, null);
    }

    /** 使用 HQL 条件和参数绑定查询，避免拼接 SQL。 */
    public Page list(int page, int size, String actor, String action, String resource) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        var conditions = new ArrayList<String>();
        var parameters = new ArrayList<Object>();
        if (actor != null && !actor.isBlank()) {
            conditions.add("actorUsername like ?" + (parameters.size() + 1));
            parameters.add("%" + actor.trim() + "%");
        }
        if (action != null && !action.isBlank()) {
            conditions.add("action = ?" + (parameters.size() + 1));
            parameters.add(action.trim());
        }
        if (resource != null && !resource.isBlank()) {
            conditions.add("resource = ?" + (parameters.size() + 1));
            parameters.add(resource.trim());
        }
        String queryText = conditions.isEmpty() ? "" : "where " + String.join(" and ", conditions);
        PanacheQuery<OperationLogEntity> query = find(queryText, Sort.by("id", Sort.Direction.Descending), parameters.toArray());
        long total = query.count();
        List<OperationLog> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize)).list().stream()
                .map(OperationLogEntity::toModel)
                .toList();
        return new Page(items, safePage, safeSize, total);
    }

    /** 使用参数化 HQL 批量删除指定记录。 */
    @Transactional
    public int delete(List<Long> ids) {
        if (ids == null || ids.isEmpty()) return 0;
        return (int) delete("id in ?1", ids);
    }

    public record Page(List<OperationLog> items, int page, int size, long total) {
    }
}
