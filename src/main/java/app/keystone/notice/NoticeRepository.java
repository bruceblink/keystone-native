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
                : "order by coalesce(publishAt, createdAt) desc, id desc";
        var result = publicOnly ? find(query, java.time.Instant.now()) : find(query);
        return result.list().stream().map(NoticeEntity::toModel).toList();
    }

    @Transactional
    public Notice create(AuthorizationContext context, String title, String content, String type, String createdBy) {
        authorization.require(context, "notice:create", "notice");
        require(title, "title");
        require(content, "content");
        try {
            NoticeEntity entity = new NoticeEntity(title, content, type, createdBy);
            persistAndFlush(entity);
            return entity.toModel();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not create notice", e);
        }
    }

    @Transactional
    public Notice update(AuthorizationContext context, String id, String title, String content, String type, Boolean enabled) {
        authorization.require(context, "notice:update", "notice");
        NoticeEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        entity.update(title, content, type, enabled);
        return entity.toModel();
    }

    @Transactional
    public Notice publish(AuthorizationContext context, String id, boolean published) {
        authorization.require(context, "notice:update", "notice");
        NoticeEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        entity.publish(published);
        return entity.toModel();
    }

    @Transactional
    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "notice:delete", "notice");
        NoticeEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        delete(entity);
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }
}
