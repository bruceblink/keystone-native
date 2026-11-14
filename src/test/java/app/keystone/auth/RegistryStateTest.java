package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 registry 的状态、过期和 key 标识边界。 */
class RegistryStateTest {
    @Test
    void acceptsOnlyUsableStatesAndFutureExpiry() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        assertTrue(RegistryState.usable(RegistryState.ACTIVE, null, now));
        assertTrue(RegistryState.usable(RegistryState.RETIRING, now.plusSeconds(1), now));
        assertFalse(RegistryState.usable(RegistryState.RETIRING, now, now));
        assertFalse(RegistryState.usable("DISABLED", null, now));
    }

    @Test
    void rejectsUnknownStateAndUnsafeKeyId() {
        assertThrows(IllegalArgumentException.class, () -> RegistryState.requireState("DISABLED"));
        assertThrows(IllegalStateException.class, () -> RegistryState.requireKeyId("../private"));
    }
}
