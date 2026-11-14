package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** 使用行锁保存和一次性消费 OIDC 授权请求。 */
@ApplicationScoped
public class OidcAuthRequestRepository implements PanacheRepositoryBase<OidcAuthRequestEntity, UUID> {
    @Transactional
    public void create(String stateHash, String nonceHash, String codeChallenge, String codeVerifier, String clientId,
                       String redirectUri, Instant expiresAt) {
        persistAndFlush(new OidcAuthRequestEntity(stateHash, nonceHash, codeChallenge, codeVerifier, clientId, redirectUri, expiresAt));
    }

    /** 状态、有效期和一次性消费必须在同一行锁事务内检查。 */
    @Transactional
    public Optional<OidcAuthRequestEntity> consume(String stateHash, Instant now) {
        OidcAuthRequestEntity request = find("stateHash", stateHash)
                .withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (request == null || request.consumedAt() != null || !request.expiresAt().isAfter(now)) return Optional.empty();
        request.consume(now);
        return Optional.of(request);
    }

    /** Provider 返回错误时也消费状态，避免同一个回调状态被重放。 */
    @Transactional
    public boolean cancel(String stateHash, Instant now) {
        OidcAuthRequestEntity request = find("stateHash", stateHash)
                .withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (request == null || request.consumedAt() != null || !request.expiresAt().isAfter(now)) return false;
        request.consume(now);
        return true;
    }

    @Transactional
    public long deleteExpired(Instant now) {
        return delete("expiresAt <= ?1 or consumedAt <= ?2", now, now.minusSeconds(900));
    }
}
