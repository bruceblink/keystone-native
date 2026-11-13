package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import java.util.UUID;

/** 使用 Panache 读取和锁定一次性恢复码。 */
@ApplicationScoped
public class MfaRecoveryCodeOrmRepository implements PanacheRepositoryBase<MfaRecoveryCodeEntity, UUID> {
    MfaRecoveryCodeEntity findByUserAndHash(String userId, String codeHash) {
        return find("userId = ?1 and codeHash = ?2", userId, codeHash).firstResult();
    }

    MfaRecoveryCodeEntity findForUpdate(String userId, String codeHash) {
        return find("userId = ?1 and codeHash = ?2", userId, codeHash)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
    }

    long deleteByUser(String userId) {
        return delete("userId", userId);
    }
}
