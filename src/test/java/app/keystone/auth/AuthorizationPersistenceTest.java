package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证授权决策和访问令牌签发使用 ORM 权限读取边界。 */
class AuthorizationPersistenceTest {
    @Test
    void authorizationPathsUseOrmUserRepository() throws Exception {
        String authorization = Files.readString(Path.of("src/main/java/app/keystone/auth/AuthorizationService.java"));
        String token = Files.readString(Path.of("src/main/java/app/keystone/auth/AccessTokenService.java"));

        assertTrue(authorization.contains("ApiKeyUserRepository"));
        assertTrue(token.contains("ApiKeyUserRepository"));
        assertFalse(authorization.contains("import app.keystone.user.UserRepository"));
        assertFalse(token.contains("DataSource"));
        assertFalse(token.contains("prepareStatement"));
    }
}
