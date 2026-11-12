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

    @Test
    void validatesIdentifiersAndVerificationStateBeforeDatabaseAccess() {
        var encrypted = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]))
                .encrypt(7L, mfaId, 1, "JBSWY3DPEHPK3PXP");
        assertThrows(IllegalArgumentException.class, () -> repository.findStatus(0));
        assertThrows(IllegalArgumentException.class, () -> repository.find(7L, "mfa-1"));
        assertThrows(IllegalArgumentException.class, () -> repository.replacePendingEnrollment(7L, mfaId, null));
        assertThrows(IllegalArgumentException.class, () -> repository.acceptTotp(7L, mfaId, -1, false));
        assertThrows(IllegalArgumentException.class, () -> repository.enableEnrollment(7L, ""));
        assertTrue(encrypted.ciphertext().length > 0);
        assertThrows(IllegalArgumentException.class, () -> repository.replaceRecoveryCodes(7L, "batch", List.of("bad")));
        assertThrows(IllegalArgumentException.class, () -> repository.consumeRecoveryCode(7L, "bad"));
    }

    @Test
    void storedMfaRecordKeepsEncryptedPayloadBounded() {
        var encrypted = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]))
                .encrypt(7L, mfaId, 1, "JBSWY3DPEHPK3PXP");
        var stored = new MfaRepository.StoredMfa(mfaId, 7L, encrypted, false, null, null);
        assertTrue(stored.encrypted().ciphertext().length > 16);
        assertTrue(stored.encrypted().nonce().length == 12);
    }
}
