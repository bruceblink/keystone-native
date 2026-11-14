package app.keystone.audit;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.util.List;

/** 使用 Panache 保存和查询登录日志。 */
@ApplicationScoped
public class LoginLogRepository implements PanacheRepositoryBase<LoginLogEntity, java.util.UUID> {
    @jakarta.inject.Inject AuthorizationService authorization;

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

    /** 为监控摘要返回总量；监控统计不应暴露无授权的分页查询入口。 */
    public long countAll() {
        return count();
    }

    /** 在审计资源范围内分页读取登录日志，避免列表入口绕过统一授权检查。 */
    @Transactional
    public Page list(AuthorizationContext context, int page, int size, String username, String status) {
        authorization.require(context, "login-log:read", "audit");
        return listPage(page, size, username, status);
    }

    private Page listPage(int page, int size, String username, String status) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        var query = query(username, status);
        long total = query.count();
        List<LoginLog> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(LoginLogEntity::toModel).toList();
        return new Page(items, safePage, safeSize, total);
    }

    /** 导出完整筛选结果；登录日志与审计资源共享 ALL/TENANT 范围。 */
    @Transactional
    public List<LoginLog> export(AuthorizationContext context, String username, String status) {
        authorization.require(context, "login-log:export", "audit");
        return query(username, status).list().stream().map(LoginLogEntity::toModel).toList();
    }

    /** 在授权范围内原子删除登录日志；目标缺失时整个事务回滚。 */
    @Transactional
    public int delete(AuthorizationContext context, List<String> ids) {
        authorization.require(context, "login-log:delete", "audit");
        if (ids == null || ids.isEmpty()) return 0;
        var values = ids.stream().filter(java.util.Objects::nonNull).map(app.keystone.identity.UuidValues::parse).distinct().toList();
        if (values.isEmpty()) return 0;
        long existing = count("id in ?1", values);
        if (existing != values.size()) throw new java.util.NoSuchElementException("login log not found");
        int deleted = (int) delete("id in ?1", values);
        if (deleted != values.size()) throw new java.util.NoSuchElementException("login log not found");
        return deleted;
    }

    private PanacheQuery<LoginLogEntity> query(String username, String status) {
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
