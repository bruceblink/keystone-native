package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.UUID;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaRepositoryTest {
    private final MfaRepository repository = new MfaRepository();
    private final String mfaId = UUID.randomUUID().toString();
    private static final String USER_ID = "00000000-0000-7000-8000-000000000007";

    @Test
    void validatesIdentifiersAndVerificationStateBeforeDatabaseAccess() {
        var encrypted = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]))
                .encrypt(USER_ID, mfaId, 1, "JBSWY3DPEHPK3PXP");
        String challengeId = UUID.randomUUID().toString();
        assertThrows(IllegalArgumentException.class, () -> repository.findStatus("not-a-uuid"));
        assertThrows(IllegalArgumentException.class, () -> repository.find(USER_ID, "mfa-1"));
        assertThrows(IllegalArgumentException.class, () -> repository.replacePendingEnrollment(USER_ID, mfaId, null));
        assertThrows(IllegalArgumentException.class, () -> repository.acceptTotp(USER_ID, mfaId, -1, false));
        assertThrows(IllegalArgumentException.class, () -> repository.enableEnrollment(USER_ID, ""));
        assertTrue(encrypted.ciphertext().length > 0);
        assertThrows(IllegalArgumentException.class, () -> repository.replaceRecoveryCodes(USER_ID, "batch", List.of("bad")));
        assertThrows(IllegalArgumentException.class, () -> repository.consumeRecoveryCode(USER_ID, "bad"));
        assertThrows(IllegalArgumentException.class, () -> repository.completeEnrollment("not-a-uuid", challengeId, "web", null,
                mfaId, 1, UUID.randomUUID().toString(), List.of("a".repeat(64))));
        assertThrows(IllegalArgumentException.class, () -> repository.consumeLoginTotp(USER_ID, challengeId, "web", null, mfaId, -1));
        assertThrows(IllegalArgumentException.class, () -> repository.consumeLoginRecovery(USER_ID, challengeId, "web", null, mfaId, "bad"));
    }

    @Test
    void storedMfaRecordKeepsEncryptedPayloadBounded() {
        var encrypted = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]))
                .encrypt(USER_ID, mfaId, 1, "JBSWY3DPEHPK3PXP");
        var stored = new MfaRepository.StoredMfa(mfaId, USER_ID, encrypted, false, null, null);
        assertTrue(stored.encrypted().ciphertext().length > 16);
        assertTrue(stored.encrypted().nonce().length == 12);
    }
}
