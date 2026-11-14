package app.keystone.post;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

/** 岗位管理入口；具体持久化由 Panache Repository 负责。 */
@ApplicationScoped
public class PostRepository implements PanacheRepositoryBase<PostEntity, java.util.UUID> {
    @jakarta.inject.Inject AuthorizationService authorization;

    @Transactional
    public List<Post> list(AuthorizationContext context) {
        authorization.require(context, "post:read", "post");
        return find("order by sortOrder, id").list().stream().map(PostEntity::toModel).toList();
    }

    @Transactional
    public Post create(AuthorizationContext context, String code, String name, Integer sortOrder) {
        authorization.require(context, "post:create", "post");
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
}
