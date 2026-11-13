package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaRateLimiterTest {
    @Test
    void normalizesAddressAndStoresOnlyHashedDimensions() {
        assertEquals("127.0.0.1", MfaRateLimiter.normalizeIp(" 127.0.0.1 "));
        assertEquals("127.0.0.1", MfaRateLimiter.normalizeIp("127.0.0.1, 10.0.0.1"));
        assertEquals("unknown", MfaRateLimiter.normalizeIp("not-an-ip"));
        var keys = MfaRateLimiter.keys(7L, "127.0.0.1");
        assertEquals(2, keys.size());
        assertTrue(keys.stream().allMatch(value -> value.matches("[0-9a-f]{64}")));
        assertNotEquals("127.0.0.1", keys.get(1));
        assertNotEquals("7", keys.get(0));
    }

    @Test
    void rejectsInvalidUserBeforeDatabaseAccess() {
        var limiter = new MfaRateLimiter();
        assertThrows(IllegalArgumentException.class, () -> limiter.isBlocked(0L, "127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> limiter.recordFailure(-1L, "127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> limiter.clear(0L, "127.0.0.1"));
    }

    @Test
    void migrationUsesAHashOnlyPrimaryKey() throws Exception {
        String sql = java.nio.file.Files.readString(java.nio.file.Path.of("src/main/resources/db/migration/V41__mfa_rate_limit.sql"));
        assertTrue(sql.contains("scope_key CHAR(64) PRIMARY KEY"));
        assertTrue(sql.contains("CREATE TABLE IF NOT EXISTS"));
        assertTrue(!sql.contains("ip_address") && !sql.contains("user_id"));
    }

    @Test
    void limiterUsesPanacheRepositoryInsteadOfJdbc() throws Exception {
        String source = java.nio.file.Files.readString(java.nio.file.Path.of(
                "src/main/java/app/keystone/auth/MfaRateLimiter.java"));
        assertTrue(source.contains("MfaRateLimitRepository"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
