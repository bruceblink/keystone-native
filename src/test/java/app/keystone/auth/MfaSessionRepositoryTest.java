package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaSessionRepositoryTest {
    private final MfaSessionRepository repository = new MfaSessionRepository();
    private static final String USER_ID = "00000000-0000-7000-8000-000000000007";

    @Test
    void rejectsUnboundOrMalformedSessionStateBeforeDatabaseAccess() {
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("", USER_ID, "web", "AAL2", "otp"));
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("session-1", "not-a-uuid", "web", "AAL2", "otp"));
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("session-1", USER_ID, "", "AAL2", "otp"));
        assertThrows(IllegalArgumentException.class, () -> repository.markVerified("session-1", USER_ID, "web", "AAL2", "otp;drop"));
    }

    @Test
    void rejectsInvalidFreshnessWindowBeforeDatabaseAccess() {
        assertThrows(IllegalArgumentException.class, () -> repository.hasRecentStepUp("session-1", USER_ID, "web", Duration.ZERO, "AAL2"));
        assertThrows(IllegalArgumentException.class, () -> repository.hasRecentStepUp("session-1", USER_ID, "web", Duration.ofHours(25), "AAL2"));
        assertThrows(IllegalArgumentException.class, () -> repository.hasRecentStepUp("session-1", USER_ID, "web", Duration.ofMinutes(10), ""));
    }
}
