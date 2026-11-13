package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 MFA 会话状态复用会话 ORM，不重新引入 JDBC。 */
class MfaSessionPersistenceTest {
    @Test
    void repositoryUsesSessionOrm() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/MfaSessionRepository.java"));

        assertTrue(source.contains("AuthSessionRepository"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
