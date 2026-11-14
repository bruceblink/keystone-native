package app.keystone.audit;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.time.Instant;
import java.util.List;

/** Persists security boundary events without storing credential material. */
@ApplicationScoped
public class SecurityEventRepository implements PanacheRepository<SecurityEventEntity> {

    public void record(String eventType, String actor, String credentialType, String sourceIp,
                       String resource, String action, String outcome, String detail) {
        record(eventType, actor, credentialType, null, sourceIp, resource, action, outcome, Context.empty(), detail);
    }

    /** 记录非秘密凭据标识，便于区分同一主体下的多个 API Key。 */
    @Transactional
    public void record(String eventType, String actor, String credentialType, String credentialId,
                       String sourceIp, String resource, String action, String outcome, String detail) {
        record(eventType, actor, credentialType, credentialId, sourceIp, resource, action, outcome, Context.empty(), detail);
    }

    /** 保存授权决策关联的会话、批准范围和请求标识。 */
    @Transactional
    public void record(String eventType, String actor, String credentialType, String credentialId,
                       String sourceIp, String resource, String action, String outcome,
                       Context context, String detail) {
        try {
            Context safeContext = context == null ? Context.empty() : context;
            persistAndFlush(new SecurityEventEntity(
                    bounded(eventType, 32),
                    bounded(actor, 128),
                    bounded(credentialType, 32),
                    bounded(credentialId, 128),
                    bounded(sourceIp, 64),
                    bounded(resource, 128),
                    bounded(action, 128),
                    bounded(outcome, 32),
                    safeContext.sessionId(),
                    bounded(safeContext.scope(), 4096),
                    bounded(safeContext.requestId(), 128),
                    bounded(detail, 255)));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not record security event", e);
        }
    }

    /** 按保留时间和总量上限分批删除最早的安全事件，避免单次事务占用过多资源。 */
    @Transactional
    public CleanupResult cleanup(SecurityEventRetentionPolicy policy, Instant now) {
        if (policy == null) throw new IllegalArgumentException("security event retention policy is required");
        Instant cutoff = policy.cutoff(now);
        int batchSize = policy.cleanupBatchSize();
        List<SecurityEventEntity> expired = find("createdAt < ?1 order by createdAt", cutoff)
                .page(io.quarkus.panache.common.Page.of(0, batchSize)).list();
        expired.forEach(this::delete);
        long expiredDeleted = expired.size();

        long beforeCapacity = count();
        long overflow = Math.max(0, beforeCapacity - policy.maxEvents());
        int capacityBatch = (int) Math.min(overflow, batchSize);
        List<SecurityEventEntity> overCapacity = capacityBatch == 0 ? List.of()
                : find("order by createdAt").page(io.quarkus.panache.common.Page.of(0, capacityBatch)).list();
        overCapacity.forEach(this::delete);
        long deleted = expiredDeleted + overCapacity.size();
        return new CleanupResult(deleted, count());
    }

    private static String bounded(String value, int maxLength) {
        if (value == null) return null;
        String normalized = value.trim();
        if (normalized.length() > maxLength) throw new IllegalArgumentException("security event field is too long");
        return normalized;
    }

    public record Context(String sessionId, String scope, String requestId) {
        public static Context empty() {
            return new Context(null, null, null);
        }
    }

    public record CleanupResult(long deleted, long remaining) {
    }
}
