package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证会话仓储通过 Panache 访问数据库，不重新引入 JDBC 和手写 SQL。 */
class SessionRepositoryTest {
    @Test
    void repositoryUsesOrmRepositories() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/SessionRepository.java"));

        assertTrue(source.contains("AuthSessionRepository"));
        assertTrue(source.contains("RefreshTokenRepository"));
        assertTrue(source.contains("RefreshTokenEventRepository"));
        assertTrue(source.contains("@Transactional"));
        assertTrue(source.contains("UserRepository ignoredUsers"));
        assertFalse(source.contains("users.findAuthUser"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("PreparedStatement"));
        assertFalse(source.contains("prepareStatement"));
    }
}
