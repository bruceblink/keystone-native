package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证 JWT 启动配置的关键失败边界。 */
class JwtConfigurationStartupCheckTest {
    @Test
    void rejectsMissingKeyLocations() {
        assertThrows(IllegalStateException.class,
                () -> JwtConfigurationStartupCheck.requireReadable("JWT public key", ""));
    }
}
