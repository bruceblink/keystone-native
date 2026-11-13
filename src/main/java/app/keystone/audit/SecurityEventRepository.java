package app.keystone.audit;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

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
}
