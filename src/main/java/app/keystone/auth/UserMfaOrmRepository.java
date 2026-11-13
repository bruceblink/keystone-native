package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;

/** 使用 Panache 读取和锁定用户 TOTP 状态。 */
@ApplicationScoped
public class UserMfaOrmRepository implements PanacheRepositoryBase<UserMfaEntity, String> {
    UserMfaEntity findByUserAndId(String userId, String mfaId) {
        return find("userId = ?1 and id = ?2", userId, mfaId).firstResult();
    }

    UserMfaEntity findForUpdate(String userId, String mfaId) {
        return find("userId = ?1 and id = ?2", userId, mfaId)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
    }

    UserMfaEntity findByUser(String userId) {
        return find("userId", userId).firstResult();
    }

    UserMfaEntity findByUserForUpdate(String userId) {
        return find("userId", userId).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
    }
}
