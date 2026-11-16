package app.keystone.post;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.ArrayList;
import java.util.Locale;

/** 岗位管理入口；具体持久化由 Panache Repository 负责。 */
@ApplicationScoped
public class PostRepository implements PanacheRepositoryBase<PostEntity, java.util.UUID> {
    @jakarta.inject.Inject AuthorizationService authorization;

    @Transactional
    public List<Post> list(AuthorizationContext context) {
        authorization.require(context, "post:read", "post");
        return find("order by sortOrder, id").list().stream().map(PostEntity::toModel).toList();
    }

    /** 按管理端筛选条件读取岗位当前页，并返回服务端总数。 */
    @Transactional
    public Page list(AuthorizationContext context, int page, int size, String keyword, String status) {
        authorization.require(context, "post:read", "post");
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        PanacheQuery<PostEntity> query = postQuery(keyword, status);
        long total = query.count();
        List<Post> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(PostEntity::toModel).toList();
        return new Page(items, safePage, safeSize, total);
    }

    /** 岗位导出复用全量查询和资源范围检查。 */
    @Transactional
    public List<Post> export(AuthorizationContext context) {
        authorization.require(context, "post:export", "post");
        return find("order by sortOrder, id").list().stream().map(PostEntity::toModel).toList();
    }

    @Transactional
    public Post create(AuthorizationContext context, String code, String name, Integer sortOrder) {
        return create(context, code, name, sortOrder, null);
    }

    /** 创建岗位时保留请求中的启用状态；省略字段仍使用启用默认值。 */
    @Transactional
    public Post create(AuthorizationContext context, String code, String name, Integer sortOrder, Boolean enabled) {
        authorization.require(context, "post:create", "post");
        require(code, "code");
        require(name, "name");
        try {
            PostEntity entity = new PostEntity(code, name, sortOrder == null ? 0 : sortOrder, enabled);
            persistAndFlush(entity);
            return entity.toModel();
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("post code already exists", e);
            throw new IllegalStateException("Could not create post", e);
        }
    }

    @Transactional
    public Post update(AuthorizationContext context, String id, String name, Integer sortOrder, Boolean enabled) {
        authorization.require(context, "post:update", "post");
        PostEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("post not found");
        entity.update(name, sortOrder, enabled);
        return entity.toModel();
    }

    @Transactional
    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "post:delete", "post");
        PostEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("post not found");
        delete(entity);
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

    private PanacheQuery<PostEntity> postQuery(String keyword, String status) {
        List<String> conditions = new ArrayList<>();
        List<Object> parameters = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            conditions.add("(lower(code) like ?1 or lower(name) like ?1)");
            parameters.add("%" + keyword.trim().toLowerCase(Locale.ROOT) + "%");
        }
        if (status != null && !status.isBlank()) {
            String normalized = status.trim().toLowerCase(Locale.ROOT);
            if (normalized.equals("enabled") || normalized.equals("active") || normalized.equals("true") || normalized.equals("1")) {
                conditions.add("enabled = true");
            } else if (normalized.equals("disabled") || normalized.equals("inactive") || normalized.equals("false") || normalized.equals("0")) {
                conditions.add("enabled = false");
            }
        }
        String query = conditions.isEmpty() ? "order by sortOrder, id" : String.join(" and ", conditions) + " order by sortOrder, id";
        return parameters.isEmpty() ? find(query) : find(query, parameters.toArray());
    }

    public record Page(List<Post> items, int page, int size, long total) {}
}
