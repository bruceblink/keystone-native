package app.keystone;

import app.keystone.auth.TotpService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TotpServiceTest {
    private static final String RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private final TotpService totp = new TotpService();

    @Test
    void matchesRfc6238Sha1Vectors() {
        // RFC 6238 使用八位示例；生产策略固定六位，因此断言示例的低六位。
        assertEquals("287082", totp.code(RFC_SECRET, 59));
        assertEquals("081804", totp.code(RFC_SECRET, 1_111_111_109));
        assertEquals("050471", totp.code(RFC_SECRET, 1_111_111_111));
        assertEquals("005924", totp.code(RFC_SECRET, 1_234_567_890));
        assertEquals("279037", totp.code(RFC_SECRET, 2_000_000_000));
        assertEquals("353130", totp.code(RFC_SECRET, 20_000_000_000L));
    }

    @Test
    void acceptsOneAdjacentTimeStepAndRejectsOlderCodes() {
        String current = totp.code(RFC_SECRET, 60);
        String next = totp.code(RFC_SECRET, 90);
        String old = totp.code(RFC_SECRET, 0);

        assertTrue(totp.verify(RFC_SECRET, current, 60));
        assertTrue(totp.verify(RFC_SECRET, next, 60));
        assertFalse(totp.verify(RFC_SECRET, old, 60));
        assertFalse(totp.verify(RFC_SECRET, "12345", 60));
        assertFalse(totp.verify(RFC_SECRET, "abcdef", 60));
    }

    @Test
    void generatedSecretIsBase32AndProducesSixDigitCodes() {
        String secret = totp.generateSecret();
        assertEquals(32, secret.length());
        assertTrue(secret.chars().allMatch(value -> value >= 'A' && value <= 'Z' || value >= '2' && value <= '7'));
        String code = totp.code(secret, Instant.ofEpochSecond(1_700_000_000));
        assertEquals(6, code.length());
        assertEquals(code, totp.code(secret, 1_700_000_000L));
    }

    @Test
    void rejectsWeakOrMalformedSecrets() {
        assertThrows(IllegalArgumentException.class, () -> totp.code("AAAA", 0));
        assertThrows(IllegalArgumentException.class, () -> totp.code("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", 0));
        assertThrows(IllegalArgumentException.class, () -> totp.code("GEZD=GNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 0));
        assertThrows(IllegalArgumentException.class, () -> totp.code(RFC_SECRET, -1));
        assertFalse(totp.verify(RFC_SECRET, null, 59));
        assertEquals("287082", totp.code(RFC_SECRET.toLowerCase(), 59));
    }
}
