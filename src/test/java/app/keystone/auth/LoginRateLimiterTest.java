package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证登录限流的哈希维度和 Panache 持久化边界。 */
class LoginRateLimiterTest {
    @Test
    void hashesBothCredentialAndAddressDimensions() {
        var keys = LoginRateLimiter.keys("Admin", "192.0.2.10");
        assertEquals(2, keys.size());
        assertTrue(keys.stream().allMatch(value -> value.matches("[0-9a-f]{64}")));
        assertNotEquals("Admin", keys.get(1));
        assertNotEquals("192.0.2.10", keys.get(0));
    }

    @Test
    void repositoryUsesPanacheWithoutManualJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/LoginRateLimiter.java"));
        assertTrue(source.contains("LoginRateLimitRepository"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }

    @Test
    void migrationDefinesHashedPrimaryKey() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V36__login_rate_limit.sql"));
        assertTrue(sql.contains("scope_key CHAR(64) PRIMARY KEY"));
        assertTrue(sql.contains("CREATE TABLE IF NOT EXISTS"));
        assertFalse(sql.contains("ip_address"));
        assertFalse(sql.contains("username"));
    }
}
