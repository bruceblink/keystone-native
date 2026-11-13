package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;

/** 在刷新事务内保存令牌事件。 */
@ApplicationScoped
public class RefreshTokenEventRepository implements PanacheRepository<RefreshTokenEventEntity> {
    void record(Long tokenId, String userId, String familyId, String eventType, String clientId, String detail) {
        persist(new RefreshTokenEventEntity(tokenId, userId, familyId, eventType, clientId, detail));
    }
}
