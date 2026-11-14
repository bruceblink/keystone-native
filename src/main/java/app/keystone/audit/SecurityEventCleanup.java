package app.keystone.audit;

import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.time.Instant;

/** 定时执行安全事件保留和容量清理；测试环境默认关闭以保持验收数据稳定。 */
@ApplicationScoped
public class SecurityEventCleanup {
    @Inject SecurityEventRepository repository;
    @Inject SecurityObservability observability;
    @ConfigProperty(name = "keystone.security.audit.retention-days", defaultValue = "90")
    int retentionDays;
    @ConfigProperty(name = "keystone.security.audit.max-events", defaultValue = "1000000")
    long maxEvents;
    @ConfigProperty(name = "keystone.security.audit.cleanup-batch-size", defaultValue = "500")
    int cleanupBatchSize;
    @ConfigProperty(name = "keystone.security.audit.cleanup.enabled", defaultValue = "true")
    boolean enabled;

    @PostConstruct
    void validateConfiguration() {
        new SecurityEventRetentionPolicy(retentionDays, maxEvents, cleanupBatchSize);
    }

    @Scheduled(every = "1h", identity = "security-event-retention")
    void cleanup() {
        if (!enabled) return;
        try {
            SecurityEventRetentionPolicy policy = new SecurityEventRetentionPolicy(retentionDays, maxEvents, cleanupBatchSize);
            SecurityEventRepository.CleanupResult result = repository.cleanup(policy, Instant.now());
            observability.auditCleanup(result.deleted(), result.remaining());
        } catch (RuntimeException e) {
            observability.auditCleanupFailed(e);
        }
    }
}
