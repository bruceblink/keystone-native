package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户资料和角色综合更新使用 ORM 事务与用户行锁。 */
class UserUpdatePersistenceTest {
    @Test
    void extendedUpdatesDelegateToOrmRepository() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));
        int start = source.indexOf("public User updateExtended");
        int end = source.indexOf("\n    public void markLogin", start);
        String method = source.substring(start, end);
        assertTrue(method.contains("ormUsers.updateUser"));
        assertFalse(method.contains("prepareStatement"));
        assertFalse(method.contains("UPDATE sys_user SET"));
    }

    @Test
    void ormUpdateKeepsWriteLockAndPermissionVersionBoundary() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyUserRepository.java"));
        assertTrue(source.contains("updateUser"));
        assertTrue(source.contains("PESSIMISTIC_WRITE"));
        assertTrue(source.contains("bumpPermissionVersion"));
        assertTrue(source.contains("resolveRoles"));
    }
}
