package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户删除路径使用 ORM 行锁和数据范围条件。 */
class UserDeletePersistenceTest {
    @Test
    void deletePathsDelegateToOrmRepository() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));
        int start = source.indexOf("private void delete(String id");
        int end = source.indexOf("\n    public List<String> permissions", start);
        String methods = source.substring(start, end);
        assertTrue(methods.contains("ormUsers.deleteUser"));
        assertTrue(methods.contains("ormUsers.deleteUsers"));
        assertFalse(methods.contains("prepareStatement"));
        assertFalse(methods.contains("DELETE FROM sys_user"));
    }

    @Test
    void ormDeleteKeepsScopeAndWriteLockBoundary() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyUserRepository.java"));
        assertTrue(source.contains("deleteUser"));
        assertTrue(source.contains("deleteUsers"));
        assertFalse(source.contains("username <> 'admin'"));
        assertTrue(source.contains("PESSIMISTIC_WRITE"));
        assertTrue(source.contains("DataScopeService.Scope"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
