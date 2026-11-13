package app.keystone.menu;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证菜单管理使用 ORM，不重新引入 JDBC。 */
class MenuPersistenceTest {
    @Test
    void repositoryUsesOrmAndRoleBinding() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/menu/MenuRepository.java"));
        assertTrue(source.contains("PanacheRepositoryBase<MenuEntity"));
        assertTrue(source.contains("assignRoles"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
