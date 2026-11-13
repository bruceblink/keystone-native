package app.keystone.dict;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证字典类型和字典项使用 ORM 事务。 */
class DictionaryPersistenceTest {
    @Test
    void repositoryUsesPanacheWithoutManualJdbc() throws Exception {
        String facade = Files.readString(Path.of("src/main/java/app/keystone/dict/DictionaryRepository.java"));
        String types = Files.readString(Path.of("src/main/java/app/keystone/dict/DictionaryTypeOrmRepository.java"));
        String items = Files.readString(Path.of("src/main/java/app/keystone/dict/DictionaryItemOrmRepository.java"));
        assertTrue(facade.contains("DictionaryTypeOrmRepository"));
        assertTrue(facade.contains("DictionaryItemOrmRepository"));
        assertTrue(types.contains("@Transactional"));
        assertTrue(items.contains("@Transactional"));
        assertTrue(items.contains("type.enabled = true"));
        assertFalse(facade.contains("DataSource"));
        assertFalse(facade.contains("prepareStatement"));
        assertFalse(types.contains("DataSource"));
        assertFalse(items.contains("prepareStatement"));
    }
}
