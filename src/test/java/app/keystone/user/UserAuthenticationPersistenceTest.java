package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户认证和失败锁定由 Panache 事务负责，不重新引入 JDBC。 */
class UserAuthenticationPersistenceTest {
    @Test
    void authenticationDelegatesToOrmRepository() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));
        int start = source.indexOf("public Optional<AuthUser> authenticate");
        int end = source.indexOf("\n    public Optional<AuthUser> findAuthUser", start);
        String method = source.substring(start, end);

        assertTrue(method.contains("ormUsers.authenticate"));
        assertFalse(method.contains("DataSource"));
        assertFalse(method.contains("prepareStatement"));
        assertFalse(method.contains("SELECT "));
    }

    @Test
    void ormRepositoryLocksUserBeforePasswordCheck() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyUserRepository.java"));

        assertTrue(source.contains("PESSIMISTIC_WRITE"));
        assertTrue(source.contains("BcryptUtil.matches"));
        assertTrue(source.contains("recordFailedLogin"));
        assertTrue(source.contains("clearFailedLogins"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
