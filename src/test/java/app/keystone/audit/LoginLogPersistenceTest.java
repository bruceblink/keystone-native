package app.keystone.audit;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证登录日志使用 ORM 持久化，不重新引入 JDBC。 */
class LoginLogPersistenceTest {
    @Test
    void repositoryUsesPanacheWithoutManualJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/audit/LoginLogRepository.java"));
        assertTrue(source.contains("PanacheRepository<LoginLogEntity>"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
