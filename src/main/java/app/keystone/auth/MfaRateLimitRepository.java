package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;

import java.time.Instant;

/** 使用 Panache 访问 MFA 限流记录，并集中处理行锁和过期清理。 */
@ApplicationScoped
public class MfaRateLimitRepository implements PanacheRepository<MfaRateLimitEntity> {
    MfaRateLimitEntity findByScopeKey(String scopeKey) {
        return find("scopeKey", scopeKey).firstResult();
    }

    /** 失败计数更新前锁定已有记录，保持同一事务内的串行更新。 */
    MfaRateLimitEntity findForUpdate(String scopeKey) {
        return find("scopeKey", scopeKey).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
    }

    long deleteExpired(Instant windowCutoff, Instant now) {
        return delete("(blockedUntil is null and windowStartedAt < ?1) "
                + "or (blockedUntil is not null and blockedUntil < ?2)", windowCutoff, now);
    }

    long deleteByScopeKey(String scopeKey) {
        return delete("scopeKey", scopeKey);
    }
}
