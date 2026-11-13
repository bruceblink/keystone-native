package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户列表和范围查询使用 Panache 查询，不重新引入 JDBC。 */
class UserQueryPersistenceTest {
    @Test
    void listAndFindPathsDelegateToOrmRepository() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));
        assertTrue(source.contains("ormUsers.listUsers"));
        assertTrue(source.contains("ormUsers.findUser"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
        assertFalse(source.contains("SELECT u.id"));
    }

    @Test
    void ormQueryUsesPanachePaginationAndScopeFields() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyUserRepository.java"));
        assertTrue(source.contains("PanacheQuery"));
        assertTrue(source.contains("Page.of"));
        assertTrue(source.contains("displayName like"));
        assertTrue(source.contains("deptId in"));
        assertTrue(source.contains("appendScope"));
    }
}
