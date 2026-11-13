package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaSecretCipherTest {
    private static final String USER_ID = "00000000-0000-7000-8000-000000000007";
    @Test
    void encryptsAndDecryptsWithBoundIdentity() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        var cipher = new MfaSecretCipher(key);
        var encrypted = cipher.encrypt(USER_ID, "mfa-1", 1, "JBSWY3DPEHPK3PXP");
        assertEquals("JBSWY3DPEHPK3PXP", cipher.decrypt(USER_ID, "mfa-1", encrypted));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt("00000000-0000-7000-8000-000000000008", "mfa-1", encrypted));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(USER_ID, "mfa-2", encrypted));
        assertThrows(IllegalStateException.class, () -> cipher.encrypt(USER_ID, "mfa-1", 2, "secret"));
    }

    @Test
    void refusesMissingMasterKeyOnlyWhenUsed() {
        var cipher = new MfaSecretCipher("");
        assertThrows(IllegalStateException.class, () -> cipher.encrypt(USER_ID, "mfa-1", 1, "secret"));
    }
}
