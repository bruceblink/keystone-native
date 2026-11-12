package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaSessionRepositoryTest {
    private final MfaSessionRepository repository = new MfaSessionRepository();

    @Test
    void rejectsUnboundOrMalformedSessionStateBeforeDatabaseAccess() {
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("", 7L, "web", "AAL2", "otp"));
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("session-1", 0L, "web", "AAL2", "otp"));
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("session-1", 7L, "", "AAL2", "otp"));
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("session-1", 7L, "web", "AAL2", "otp;drop"));
    }

    @Test
    void rejectsInvalidFreshnessWindowBeforeDatabaseAccess() {
        assertThrows(IllegalArgumentException.class, () -> repository.hasRecentStepUp("session-1", 7L, "web", Duration.ZERO, "AAL2"));
        assertThrows(IllegalArgumentException.class, () -> repository.hasRecentStepUp("session-1", 7L, "web", Duration.ofHours(25), "AAL2"));
        assertThrows(IllegalArgumentException.class, () -> repository.hasRecentStepUp("session-1", 7L, "web", Duration.ofMinutes(10), ""));
    }
}
