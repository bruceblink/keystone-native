package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaChallengeRepositoryTest {
    private static final String USER_ID = "00000000-0000-7000-8000-000000000007";
    @Test
    void databasePurposeValuesStayAlignedWithMigration() {
        assertEquals("LOGIN", MfaChallengeRepository.Purpose.LOGIN.value());
        assertEquals("STEP_UP", MfaChallengeRepository.Purpose.STEP_UP.value());
        assertEquals("ENROLL", MfaChallengeRepository.Purpose.ENROLL.value());
        assertEquals("RECOVERY", MfaChallengeRepository.Purpose.RECOVERY.value());
    }

    @Test
    void challengeMetadataDoesNotContainContextHash() {
        var challenge = new MfaChallengeRepository.Challenge("id", USER_ID, MfaChallengeRepository.Purpose.LOGIN,
                "web", null, Instant.parse("2030-01-01T00:00:00Z"), 0, null);
        assertNull(challenge.sessionId());
        assertEquals(0, challenge.attemptCount());
        assertNull(challenge.consumedAt());
    }

    @Test
    void transactionalHelpersValidateBeforeUsingOrm() {
        var repository = new MfaChallengeRepository();
        assertThrows(IllegalArgumentException.class,
                () -> repository.lockActiveForUpdate("not-a-uuid", "not-a-uuid", "web", MfaChallengeRepository.Purpose.LOGIN, null));
        assertThrows(IllegalArgumentException.class, () -> repository.consumeLocked(null));
    }
}
