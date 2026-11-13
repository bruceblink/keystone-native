package app.keystone.role;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证角色管理入口使用 ORM，不重新引入 JDBC。 */
class RolePersistenceTest {
    @Test
    void roleRepositoryDelegatesToOrm() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/role/RoleRepository.java"));
        assertTrue(source.contains("RoleAdminOrmRepository"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }

    @Test
    void roleOrmRepositoryUsesTransactionsAndPermissionVersions() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/RoleAdminOrmRepository.java"));
        assertTrue(source.contains("@Transactional"));
        assertTrue(source.contains("bumpPermissionVersion"));
        assertTrue(source.contains("replacePermissions"));
        assertTrue(source.contains("findUsersByIdsForUpdate"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
