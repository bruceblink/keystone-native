package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;

import java.time.Instant;
import java.util.List;

/** 使用 Panache 查询和锁定刷新令牌轮换明细。 */
@ApplicationScoped
public class RefreshTokenRepository implements PanacheRepositoryBase<RefreshTokenEntity, java.util.UUID> {
    RefreshTokenEntity findForUpdateByHash(String tokenHash) {
        return find("tokenHash", tokenHash).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
    }

    RefreshTokenEntity findByAccessToken(String accessTokenId, Instant now) {
        return find("accessTokenId = ?1 and revokedAt is null and expiresAt > ?2 and accessExpiresAt > ?2 and idleExpiresAt > ?2",
                accessTokenId, now).firstResult();
    }

    RefreshTokenEntity findByAccessTokenAndVersion(String accessTokenId, String userId, Instant now) {
        return find("accessTokenId = ?1 and userId = ?2 and revokedAt is null and expiresAt > ?3 and accessExpiresAt > ?3 and idleExpiresAt > ?3",
                accessTokenId, userId, now).firstResult();
    }

    List<RefreshTokenEntity> findByFamily(String familyId) {
        return find("refreshFamilyId", familyId).list();
    }

    List<RefreshTokenEntity> findByUser(String userId) {
        return find("userId", userId).list();
    }
}
