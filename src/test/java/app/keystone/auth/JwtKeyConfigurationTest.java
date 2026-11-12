package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证 JWT 密钥标识的配置边界，避免发行没有轮换标识的令牌。 */
class JwtKeyConfigurationTest {
    @Test
    void acceptsStableKeyIdentifiers() {
        assertEquals("rs256-2026-01", AccessTokenService.requireKeyId(" rs256-2026-01 "));
        assertEquals("prod:key.1", AccessTokenService.requireKeyId("prod:key.1"));
    }

    @Test
    void rejectsMissingOrUnsafeKeyIdentifiers() {
        assertThrows(IllegalStateException.class, () -> AccessTokenService.requireKeyId(""));
        assertThrows(IllegalStateException.class, () -> AccessTokenService.requireKeyId("key id"));
        assertThrows(IllegalStateException.class, () -> AccessTokenService.requireKeyId("../private"));
        assertThrows(IllegalStateException.class, () -> AccessTokenService.requireKeyId("a".repeat(129)));
    }
}
