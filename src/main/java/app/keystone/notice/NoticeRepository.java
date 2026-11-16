package app.keystone.notice;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.ArrayList;
import java.util.Locale;

/** 公告管理入口；具体持久化由 Panache Repository 负责。 */
@ApplicationScoped
public class NoticeRepository implements PanacheRepositoryBase<NoticeEntity, java.util.UUID> {
    @jakarta.inject.Inject AuthorizationService authorization;

    @Transactional
    public List<Notice> list(AuthorizationContext context, boolean publicOnly) {
        if (!publicOnly) authorization.require(context, "notice:read", "notice");
        String query = publicOnly
                ? "published = true and enabled = true and (publishAt is null or publishAt <= ?1) order by coalesce(publishAt, createdAt) desc, id desc"
                : ownerQuery(context, "order by coalesce(publishAt, createdAt) desc, id desc");
        var result = publicOnly
                ? find(query, java.time.Instant.now())
                : context.allScope() ? find(query) : find(query, context.subjectId());
        return result.list().stream().map(NoticeEntity::toModel).toList();
    }

    /** 按管理页面筛选条件读取公告当前页，并保留总数供前端分页。 */
    @Transactional
    public Page list(AuthorizationContext context, int page, int size, String keyword, String title,
                     String content, String noticeType, String status, Boolean published) {
        authorization.require(context, "notice:read", "notice");
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        var conditions = new ArrayList<String>();
        var parameters = new ArrayList<Object>();
        if (!context.allScope()) {
            conditions.add("ownerId = ?" + (parameters.size() + 1));
            parameters.add(context.subjectId());
        }
        appendContains(conditions, parameters, keyword, "title", "content", "noticeType");
        appendContains(conditions, parameters, title, "title");
        appendContains(conditions, parameters, content, "content");
        appendContains(conditions, parameters, noticeType == null ? null : noticeType, "noticeType");
        appendStatus(conditions, status);
        if (published != null) {
            conditions.add("published = " + published);
        }
        String queryText = String.join(" and ", conditions);
        if (queryText.isBlank()) queryText = "1 = 1";
        queryText += " order by coalesce(publishAt, createdAt) desc, id desc";
        var query = find(queryText, parameters.toArray());
        long total = query.count();
        List<Notice> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(NoticeEntity::toModel).toList();
        return new Page(items, safePage, safeSize, total);
    }

    private static void appendContains(List<String> conditions, List<Object> parameters, String value,
                                       String... fields) {
        if (value == null || value.isBlank()) return;
        int index = parameters.size() + 1;
        String pattern = "%" + value.trim().toLowerCase(Locale.ROOT) + "%";
        String expression = java.util.Arrays.stream(fields)
                .map(field -> "lower(" + field + ") like ?" + index)
                .reduce((left, right) -> left + " or " + right)
                .orElseThrow();
        conditions.add("(" + expression + ")");
        parameters.add(pattern);
    }

    private static void appendStatus(List<String> conditions, String status) {
        if (status == null || status.isBlank() || "all".equalsIgnoreCase(status)) return;
        switch (status.trim().toLowerCase(Locale.ROOT)) {
            case "published" -> conditions.add("published = true");
            case "unpublished" -> conditions.add("published = false");
            case "active", "enabled" -> conditions.add("enabled = true");
            case "inactive", "disabled" -> conditions.add("enabled = false");
            default -> { }
        }
    }

    @Transactional
    public Notice create(AuthorizationContext context, String title, String content, String type, String createdBy) {
        return create(context, title, content, type, createdBy, null);
    }

    /** 创建公告时保留管理端的启用状态；省略字段仍默认启用。 */
    @Transactional
    public Notice create(AuthorizationContext context, String title, String content, String type, String createdBy, Boolean enabled) {
        authorization.require(context, "notice:create", "notice", context.subjectId());
        require(title, "title");
        require(content, "content");
        try {
            NoticeEntity entity = new NoticeEntity(title, content, type, createdBy, context.subjectId(), enabled);
            persistAndFlush(entity);
            return entity.toModel();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not create notice", e);
        }
    }

    @Transactional
    public Notice update(AuthorizationContext context, String id, String title, String content, String type, Boolean enabled) {
        authorization.require(context, "notice:update", "notice");
        NoticeEntity entity = findFor(context, id, true);
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        authorization.require(context, "notice:update", "notice", entity.ownerId());
        entity.update(title, content, type, enabled);
        return entity.toModel();
    }

    @Transactional
    public Notice publish(AuthorizationContext context, String id, boolean published) {
        authorization.require(context, "notice:update", "notice");
        NoticeEntity entity = findFor(context, id, true);
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        authorization.require(context, "notice:update", "notice", entity.ownerId());
        entity.publish(published);
        return entity.toModel();
    }

    @Transactional
    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "notice:delete", "notice");
        NoticeEntity entity = findFor(context, id, true);
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        authorization.require(context, "notice:delete", "notice", entity.ownerId());
        delete(entity);
    }

    /** 在同一事务内锁定并删除全部目标；缺失或越界时不允许部分删除。 */
    @Transactional
    public int deleteAll(AuthorizationContext context, List<String> ids) {
        authorization.require(context, "notice:delete", "notice");
        List<java.util.UUID> uniqueIds = parseIds(ids);
        var query = context.allScope()
                ? find("id in ?1", uniqueIds)
                : find("id in ?1 and ownerId = ?2", uniqueIds, context.subjectId());
        List<NoticeEntity> entities = query.withLock(LockModeType.PESSIMISTIC_WRITE).list();
        if (entities.size() != uniqueIds.size()) throw new java.util.NoSuchElementException("notice not found");
        entities.forEach(this::delete);
        return entities.size();
    }

    /** 按主体范围读取公告；SELF 主体只能看到自己创建的新记录。 */
    private NoticeEntity findFor(AuthorizationContext context, String id, boolean lock) {
        var query = context.allScope()
                ? find("id", app.keystone.identity.UuidValues.parse(id))
                : find("id = ?1 and ownerId = ?2", app.keystone.identity.UuidValues.parse(id),
                        context.subjectId());
        return (lock ? query.withLock(LockModeType.PESSIMISTIC_WRITE) : query).firstResult();
    }

    private static String ownerQuery(AuthorizationContext context, String orderBy) {
        return context.allScope() ? orderBy : "ownerId = ?1 " + orderBy;
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    /** 规范化批量主键并去重，保持重复请求的幂等删除语义。 */
    private static List<java.util.UUID> parseIds(List<String> ids) {
        if (ids == null || ids.isEmpty()) throw new IllegalArgumentException("ids is required");
        var unique = new java.util.LinkedHashSet<java.util.UUID>();
        for (String id : ids) unique.add(app.keystone.identity.UuidValues.parse(id));
        if (unique.isEmpty()) throw new IllegalArgumentException("ids is required");
        return List.copyOf(unique);
    }

    public record Page(List<Notice> items, int page, int size, long total) {
    }
}
