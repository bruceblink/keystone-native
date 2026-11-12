package app.keystone.user;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证账户锁定的指数退避和时间上限。 */
class UserSecurityPolicyTest {
    @Test
    void lockBackoffDoublesAfterThresholdAndStopsAtCap() {
        assertEquals(60L, UserRepository.calculateLockDelaySeconds(60, 900, 5));
        assertEquals(120L, UserRepository.calculateLockDelaySeconds(60, 900, 6));
        assertEquals(240L, UserRepository.calculateLockDelaySeconds(60, 900, 7));
        assertEquals(900L, UserRepository.calculateLockDelaySeconds(60, 900, 20));
        assertThrows(IllegalArgumentException.class, () -> UserRepository.calculateLockDelaySeconds(60, 30, 5));
    }
}
