package app.keystone.audit;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.quarkus.panache.common.Sort;
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

    /**
     * 按主体、凭据和时间范围分页查询安全事件。返回字段经过脱敏，不包含 detail、scope 或令牌材料。
     */
    public ReportPage report(String actor, String credentialType, String credentialId,
                             Instant from, Instant to, int page, int size) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        var conditions = new java.util.ArrayList<String>();
        var parameters = new java.util.ArrayList<Object>();
        if (actor != null && !actor.isBlank()) {
            parameters.add(actor.trim());
            conditions.add("actor = ?" + parameters.size());
        }
        if (credentialType != null && !credentialType.isBlank()) {
            parameters.add(credentialType.trim());
            conditions.add("credentialType = ?" + parameters.size());
        }
        if (credentialId != null && !credentialId.isBlank()) {
            parameters.add(credentialId.trim());
            conditions.add("credentialId = ?" + parameters.size());
        }
        if (from != null) {
            parameters.add(from);
            conditions.add("createdAt >= ?" + parameters.size());
        }
        if (to != null) {
            parameters.add(to);
            conditions.add("createdAt < ?" + parameters.size());
        }
        String queryText = conditions.isEmpty() ? "" : "where " + String.join(" and ", conditions);
        PanacheQuery<SecurityEventEntity> query = find(queryText,
                Sort.by("createdAt", Sort.Direction.Descending), parameters.toArray());
        long total = query.count();
        List<Event> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(SecurityEventRepository::toEvent).toList();
        return new ReportPage(items, safePage, safeSize, total);
    }

    private static Event toEvent(SecurityEventEntity event) {
        return new Event(event.getId(), event.getEventType(), event.getActor(), event.getCredentialType(),
                event.getCredentialId(), event.getSourceIp(), event.getResource(), event.getAction(),
                event.getOutcome(), event.getRequestId(), event.getCreatedAt());
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

    public record ReportPage(List<Event> items, int page, int size, long total) {
    }

    public record Event(String id, String eventType, String actor, String credentialType, String credentialId,
                        String sourceIp, String resource, String action, String outcome, String requestId,
                        Instant createdAt) {
    }
}
