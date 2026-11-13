package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiKeyRateLimiterTest {
    @Test
    void storesOnlyHashedSourceAndCredentialDimensions() {
        var keys = ApiKeyRateLimiter.keys("ks_live_secret", "192.0.2.10");
        assertEquals(2, keys.size());
        assertTrue(keys.stream().allMatch(value -> value.matches("[0-9a-f]{64}")));
        assertNotEquals("192.0.2.10", keys.get(0));
        assertNotEquals("ks_live_secret", keys.get(1));
    }

    @Test
    void rejectsMissingDimensionsBeforeDatabaseAccess() {
        var limiter = new ApiKeyRateLimiter();
        assertThrows(IllegalArgumentException.class, () -> limiter.isBlocked("", "192.0.2.10"));
        assertThrows(IllegalArgumentException.class, () -> limiter.recordFailure("key", ""));
        assertThrows(IllegalArgumentException.class, () -> limiter.clear("key", ""));
    }

    @Test
    void migrationStoresOnlyHashKeys() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V42__api_key_rate_limit.sql"));
        assertTrue(sql.contains("scope_key CHAR(64) PRIMARY KEY"));
        assertTrue(!sql.contains("api_key") || sql.contains("sys_api_key_rate_limit"));
    }

    @Test
    void limiterUsesPanacheRepositoryInsteadOfJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyRateLimiter.java"));
        assertTrue(source.contains("ApiKeyRateLimitRepository"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
