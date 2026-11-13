package app.keystone.post;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

/** 岗位管理入口；具体持久化由 Panache Repository 负责。 */
@ApplicationScoped
public class PostRepository implements PanacheRepositoryBase<PostEntity, Long> {
    @Transactional
    public List<Post> list() {
        return find("order by sortOrder, id").list().stream().map(PostEntity::toModel).toList();
    }

    @Transactional
    public Post create(String code, String name, Integer sortOrder) {
        require(code, "code");
        require(name, "name");
        try {
            PostEntity entity = new PostEntity(code, name, sortOrder == null ? 0 : sortOrder);
            persistAndFlush(entity);
            return entity.toModel();
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("post code already exists", e);
            throw new IllegalStateException("Could not create post", e);
        }
    }

    @Transactional
    public Post update(long id, String name, Integer sortOrder, Boolean enabled) {
        PostEntity entity = find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("post not found");
        entity.update(name, sortOrder, enabled);
        return entity.toModel();
    }

    @Transactional
    public void delete(long id) {
        PostEntity entity = find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
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
}
