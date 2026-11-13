package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;

import java.time.Instant;
import java.util.List;

/** 使用 Panache 查询和锁定独立会话状态。 */
@ApplicationScoped
public class AuthSessionRepository implements PanacheRepositoryBase<AuthSessionEntity, String> {
    AuthSessionEntity findForUpdate(String id) {
        return find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
    }

    List<AuthSessionEntity> findActiveForUser(long userId, Instant now) {
        return find("userId = ?1 and revokedAt is null and refreshExpiresAt > ?2 and idleExpiresAt > ?2",
                userId, now).withLock(LockModeType.PESSIMISTIC_WRITE).list();
    }

    List<AuthSessionEntity> findByUser(long userId) {
        return find("userId", userId).list();
    }
}
