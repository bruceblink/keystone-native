package app.keystone.notice;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

/** 公告管理入口；具体持久化由 Panache Repository 负责。 */
@ApplicationScoped
public class NoticeRepository implements PanacheRepositoryBase<NoticeEntity, java.util.UUID> {
    @Transactional
    public List<Notice> list(boolean publicOnly) {
        String query = publicOnly
                ? "published = true and enabled = true and (publishAt is null or publishAt <= ?1) order by coalesce(publishAt, createdAt) desc, id desc"
                : "order by coalesce(publishAt, createdAt) desc, id desc";
        var result = publicOnly ? find(query, java.time.Instant.now()) : find(query);
        return result.list().stream().map(NoticeEntity::toModel).toList();
    }

    @Transactional
    public Notice create(String title, String content, String type, String createdBy) {
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
    public Notice update(String id, String title, String content, String type, Boolean enabled) {
        NoticeEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        entity.update(title, content, type, enabled);
        return entity.toModel();
    }

    @Transactional
    public Notice publish(String id, boolean published) {
        NoticeEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        entity.publish(published);
        return entity.toModel();
    }

    @Transactional
    public void delete(String id) {
        NoticeEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("notice not found");
        delete(entity);
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }
}
