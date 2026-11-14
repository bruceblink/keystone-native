package app.keystone.notice;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

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

    @Transactional
    public Notice create(AuthorizationContext context, String title, String content, String type, String createdBy) {
        authorization.require(context, "notice:create", "notice", context.subjectId());
        require(title, "title");
        require(content, "content");
        try {
            NoticeEntity entity = new NoticeEntity(title, content, type, createdBy, context.subjectId());
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
}
