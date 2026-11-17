package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import io.quarkus.panache.common.Page;

import java.time.Instant;
import java.util.UUID;
import app.keystone.identity.UuidValues;

/** 使用 Panache 读取和锁定 MFA 认证请求。 */
@ApplicationScoped
public class AuthChallengeOrmRepository implements PanacheRepositoryBase<AuthChallengeEntity, UUID> {
    AuthChallengeEntity findActive(String id, String userId, String clientId, String purpose,
                                    String sessionId, Instant now, int maxAttempts) {
        return activeQuery(id, userId, clientId, purpose, sessionId, now, maxAttempts)
                .firstResult();
    }

    java.util.List<AuthChallengeEntity> listActive(String userId, String clientId, String purpose,
                                                   String sessionId, Instant now, int maxAttempts) {
        return activeQuery(null, userId, clientId, purpose, sessionId, now, maxAttempts).list();
    }

    long countStepUpCreatedSince(String userId, String sessionId, Instant createdAfter) {
        return count("userId = ?1 and sessionId = ?2 and purpose = ?3 and createdAt > ?4",
                userId, sessionId, MfaChallengeRepository.Purpose.STEP_UP.value(), createdAfter);
    }

    java.util.List<AuthChallengeEntity> listExpired(Instant now, Instant stepUpIssueCutoff, int batchSize) {
        return find("expiresAt <= ?1 and (purpose <> ?2 or createdAt <= ?3) order by expiresAt asc",
                now, MfaChallengeRepository.Purpose.STEP_UP.value(), stepUpIssueCutoff)
                .page(Page.ofSize(batchSize)).list();
    }

    long deleteByIds(java.util.List<UUID> ids) {
        return delete("id in ?1", ids);
    }

    /** 在用户行锁之后锁定认证请求，保持 MFA 事务的统一锁顺序。 */
    AuthChallengeEntity findActiveForUpdate(String id, String userId, String clientId, String purpose,
                                            String sessionId, Instant now, int maxAttempts) {
        return activeQuery(id, userId, clientId, purpose, sessionId, now, maxAttempts)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
    }

    private io.quarkus.hibernate.orm.panache.PanacheQuery<AuthChallengeEntity> activeQuery(
            String id, String userId, String clientId, String purpose, String sessionId,
            Instant now, int maxAttempts) {
        var query = new StringBuilder("userId = ?1 and clientId = ?2 and purpose = ?3 "
                + "and consumedAt is null and expiresAt > ?4 and attemptCount < ?5");
        var parameters = new java.util.ArrayList<Object>();
        parameters.add(userId);
        parameters.add(clientId);
        parameters.add(purpose);
        parameters.add(now);
        parameters.add(maxAttempts);
        if (id != null) {
            parameters.add(UuidValues.parse(id));
            query.append(" and id = ?").append(parameters.size());
        }
        if (sessionId == null) {
            query.append(" and sessionId is null");
        } else {
            parameters.add(sessionId);
            query.append(" and sessionId = ?").append(parameters.size());
        }
        query.append(" order by createdAt desc");
        return find(query.toString(), parameters.toArray());
    }
}
