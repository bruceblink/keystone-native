package app.keystone.audit;

import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.concurrent.atomic.LongAdder;

/** 汇总认证异常和安全事件清理结果，提供运行期指标和低噪声告警日志。 */
@ApplicationScoped
public class SecurityObservability {
    private static final Logger LOG = Logger.getLogger(SecurityObservability.class);
    private final LongAdder loginFailures = new LongAdder();
    private final LongAdder loginBlocked = new LongAdder();
    private final LongAdder mfaFailures = new LongAdder();
    private final LongAdder mfaBlocked = new LongAdder();
    private final LongAdder apiKeyFailures = new LongAdder();
    private final LongAdder apiKeyBlocked = new LongAdder();
    private final LongAdder auditEventsDeleted = new LongAdder();
    private final LongAdder auditCleanupFailures = new LongAdder();
    private volatile Instant lastAuditCleanupAt;

    /** 记录密码登录失败；达到阻断阈值时输出不包含主体和地址的告警。 */
    public void loginFailure(boolean blocked) {
        loginFailures.increment();
        if (blocked) {
            loginBlocked.increment();
            LOG.warn("security alert event=login_rate_limited");
        }
    }

    /** 记录 MFA 验证失败；阻断告警不包含验证码和主体标识。 */
    public void mfaFailure(boolean blocked) {
        mfaFailures.increment();
        if (blocked) {
            mfaBlocked.increment();
            LOG.warn("security alert event=mfa_rate_limited");
        }
    }

    /** 记录 API Key 失败；只在来源或凭据桶被阻断时输出告警。 */
    public void apiKeyFailure(boolean blocked) {
        apiKeyFailures.increment();
        if (blocked) {
            apiKeyBlocked.increment();
            LOG.warn("security alert event=api_key_rate_limited");
        }
    }

    /** 保存最近一次清理结果，并累计删除数量。 */
    public void auditCleanup(long deleted, long remaining) {
        if (deleted > 0) auditEventsDeleted.add(deleted);
        lastAuditCleanupAt = Instant.now();
        LOG.infof("security audit cleanup completed deleted=%d remaining=%d", deleted, remaining);
    }

    /** 记录清理失败；失败不会中断认证请求，但会保留可检索的错误日志。 */
    public void auditCleanupFailed(Throwable failure) {
        auditCleanupFailures.increment();
        LOG.error("security audit cleanup failed", failure);
    }

    public Metrics snapshot() {
        return new Metrics(loginFailures.sum(), loginBlocked.sum(), mfaFailures.sum(), mfaBlocked.sum(),
                apiKeyFailures.sum(), apiKeyBlocked.sum(), auditEventsDeleted.sum(), auditCleanupFailures.sum(), lastAuditCleanupAt);
    }

    public record Metrics(long loginFailures, long loginBlocked, long mfaFailures, long mfaBlocked,
                          long apiKeyFailures, long apiKeyBlocked, long auditEventsDeleted,
                          long auditCleanupFailures, Instant lastAuditCleanupAt) {
    }
}
