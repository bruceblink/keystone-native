package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class MfaChallengeRepositoryTest {
    @Test
    void databasePurposeValuesStayAlignedWithMigration() {
        assertEquals("LOGIN", MfaChallengeRepository.Purpose.LOGIN.value());
        assertEquals("STEP_UP", MfaChallengeRepository.Purpose.STEP_UP.value());
        assertEquals("ENROLL", MfaChallengeRepository.Purpose.ENROLL.value());
        assertEquals("RECOVERY", MfaChallengeRepository.Purpose.RECOVERY.value());
    }

    @Test
    void challengeMetadataDoesNotContainContextHash() {
        var challenge = new MfaChallengeRepository.Challenge("id", 7L, MfaChallengeRepository.Purpose.LOGIN,
                "web", null, Instant.parse("2030-01-01T00:00:00Z"), 0, null);
        assertNull(challenge.sessionId());
        assertEquals(0, challenge.attemptCount());
        assertNull(challenge.consumedAt());
    }
}
