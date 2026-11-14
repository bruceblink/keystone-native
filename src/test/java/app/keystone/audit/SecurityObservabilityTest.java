package app.keystone.audit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 验证认证异常和安全事件清理指标的累计行为。 */
class SecurityObservabilityTest {
    @Test
    void accumulatesFailuresAndCleanupResults() {
        var metrics = new SecurityObservability();
        metrics.loginFailure(false);
        metrics.loginFailure(true);
        metrics.mfaFailure(true);
        metrics.apiKeyFailure(false);
        metrics.auditCleanup(7, 90);

        var snapshot = metrics.snapshot();
        assertEquals(2, snapshot.loginFailures());
        assertEquals(1, snapshot.loginBlocked());
        assertEquals(1, snapshot.mfaFailures());
        assertEquals(1, snapshot.mfaBlocked());
        assertEquals(1, snapshot.apiKeyFailures());
        assertEquals(0, snapshot.apiKeyBlocked());
        assertEquals(7, snapshot.auditEventsDeleted());
        assertEquals(0, snapshot.auditCleanupFailures());
    }
}
