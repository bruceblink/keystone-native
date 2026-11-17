package app.keystone.auth;

import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

/** 定时分批清理已过期的 MFA 认证请求。 */
@ApplicationScoped
public class MfaChallengeCleanup {
    private static final Logger LOG = Logger.getLogger(MfaChallengeCleanup.class.getName());

    @Inject MfaChallengeRepository challenges;
    @ConfigProperty(name = "keystone.security.mfa.challenge-cleanup.enabled", defaultValue = "true")
    boolean enabled;
    @ConfigProperty(name = "keystone.security.mfa.challenge-cleanup.batch-size", defaultValue = "500")
    int batchSize;
    @ConfigProperty(name = "keystone.security.mfa.step-up.issue.window-seconds", defaultValue = "60")
    long stepUpIssueWindowSeconds;

    @PostConstruct
    void validateConfiguration() {
        if (batchSize < 1 || batchSize > 10_000 || stepUpIssueWindowSeconds < 1) {
            throw new IllegalStateException("MFA challenge cleanup configuration is invalid");
        }
    }

    /** 每次扫描固定上限数量；清理失败时记录错误，下一轮继续处理。 */
    @Scheduled(every = "1m", identity = "mfa-auth-challenge-expiry-cleanup")
    void cleanupExpired() {
        if (!enabled) return;
        try {
            Instant now = Instant.now();
            int deleted = challenges.deleteExpiredBatch(now, now.minusSeconds(stepUpIssueWindowSeconds), batchSize);
            if (deleted > 0) LOG.info("Expired MFA challenges deleted: " + deleted);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Expired MFA challenge cleanup failed", e);
        }
    }
}
