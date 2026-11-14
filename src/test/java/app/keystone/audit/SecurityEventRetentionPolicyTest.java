package app.keystone.audit;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证安全事件保留天数、总量和单次清理批量的边界。 */
class SecurityEventRetentionPolicyTest {
    @Test
    void computesRetentionCutoff() {
        var now = Instant.parse("2026-11-14T00:00:00Z");
        var policy = new SecurityEventRetentionPolicy(30, 100_000, 500);
        assertEquals(Instant.parse("2026-10-15T00:00:00Z"), policy.cutoff(now));
    }

    @Test
    void rejectsUnsafeBounds() {
        assertThrows(IllegalArgumentException.class, () -> new SecurityEventRetentionPolicy(0, 100_000, 500));
        assertThrows(IllegalArgumentException.class, () -> new SecurityEventRetentionPolicy(30, 99, 500));
        assertThrows(IllegalArgumentException.class, () -> new SecurityEventRetentionPolicy(30, 100_000, 0));
    }
}
