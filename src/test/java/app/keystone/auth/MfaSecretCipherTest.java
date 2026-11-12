package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaSecretCipherTest {
    @Test
    void encryptsAndDecryptsWithBoundIdentity() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        var cipher = new MfaSecretCipher(key);
        var encrypted = cipher.encrypt(7L, "mfa-1", 1, "JBSWY3DPEHPK3PXP");
        assertEquals("JBSWY3DPEHPK3PXP", cipher.decrypt(7L, "mfa-1", encrypted));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(8L, "mfa-1", encrypted));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(7L, "mfa-2", encrypted));
        assertThrows(IllegalStateException.class, () -> cipher.encrypt(7L, "mfa-1", 2, "secret"));
    }

    @Test
    void refusesMissingMasterKeyOnlyWhenUsed() {
        var cipher = new MfaSecretCipher("");
        assertThrows(IllegalStateException.class, () -> cipher.encrypt(7L, "mfa-1", 1, "secret"));
    }
}
