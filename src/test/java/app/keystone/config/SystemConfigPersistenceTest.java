package app.keystone.config;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证系统配置使用 ORM，不重新引入 JDBC。 */
class SystemConfigPersistenceTest {
    @Test
    void repositoryUsesPanacheWithoutManualJdbc() throws Exception {
        String facade = Files.readString(Path.of("src/main/java/app/keystone/config/SystemConfigRepository.java"));
        String orm = Files.readString(Path.of("src/main/java/app/keystone/config/SystemConfigOrmRepository.java"));
        assertTrue(facade.contains("SystemConfigOrmRepository"));
        assertTrue(orm.contains("@Transactional"));
        assertTrue(orm.contains("PESSIMISTIC_WRITE"));
        assertFalse(facade.contains("DataSource"));
        assertFalse(facade.contains("prepareStatement"));
        assertFalse(orm.contains("DataSource"));
        assertFalse(orm.contains("prepareStatement"));
    }
}
