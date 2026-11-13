package app.keystone.audit;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.util.List;

/** 使用 Panache 保存和查询登录日志。 */
@ApplicationScoped
public class LoginLogRepository implements PanacheRepositoryBase<LoginLogEntity, java.util.UUID> {
    /** 登录日志写入失败不影响认证主流程。 */
    @Transactional
    public void record(String username, String status, String ipAddress, String message, String userAgent) {
        try {
            persist(new LoginLogEntity(username == null || username.isBlank() ? "unknown" : username,
                    status, ipAddress, message, userAgent));
        } catch (RuntimeException ignored) {
            // 日志写入失败不能改变登录响应；调用方通过运行指标观察持久化异常。
        }
    }

    @Transactional
    public Page list(int page, int size, String username, String status) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        var query = findQuery(username, status);
        long total = query.count();
        List<LoginLog> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(LoginLogEntity::toModel).toList();
        return new Page(items, safePage, safeSize, total);
    }

    @Transactional
    public int delete(List<String> ids) {
        if (ids == null || ids.isEmpty()) return 0;
        int total = 0;
        for (String id : ids) {
            if (id != null && delete("id", app.keystone.identity.UuidValues.parse(id)) > 0) total++;
        }
        return total;
    }

    private io.quarkus.hibernate.orm.panache.PanacheQuery<LoginLogEntity> findQuery(String username, String status) {
        var query = new StringBuilder("1 = 1");
        var parameters = new java.util.ArrayList<Object>();
        if (username != null && !username.isBlank()) {
            parameters.add("%" + username.trim() + "%");
            query.append(" and username like ?").append(parameters.size());
        }
        if (status != null && !status.isBlank()) {
            parameters.add(status.trim());
            query.append(" and status = ?").append(parameters.size());
        }
        query.append(" order by id desc");
        return find(query.toString(), parameters.toArray());
    }

    public record Page(List<LoginLog> items, int page, int size, long total) {
    }
}
