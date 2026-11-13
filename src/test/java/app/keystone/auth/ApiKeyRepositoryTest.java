package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 API Key 主记录仓储保持 ORM 边界，不重新引入 JDBC。 */
class ApiKeyRepositoryTest {
    @Test
    void repositoryUsesPanacheWithoutManualJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyRepository.java"));

        assertTrue(source.contains("PanacheRepository<ApiKeyEntity>"));
        assertTrue(source.contains("ApiKeyUserRepository"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("import app.keystone.user.UserRepository"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("PreparedStatement"));
        assertFalse(source.contains("prepareStatement"));
    }
}
