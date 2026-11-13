package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户认证只读路径委托到 ORM，不重新拼接查询 SQL。 */
class UserReadPersistenceTest {
    @Test
    void authenticationReadsUseOrmRepository() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));

        assertTrue(source.contains("ApiKeyUserRepository ormUsers"));
        assertTrue(source.contains("ormUsers.findAuthUser(id)"));
        assertTrue(source.contains("ormUsers.findAuthUserByUsername(username)"));
        assertTrue(source.contains("ormUsers.permissions(userId)"));
        assertTrue(source.contains("ormUsers.permissionVersion(userId)"));
        assertTrue(source.contains("ormUsers.markLogin(id, ip)"));
        assertFalse(source.contains("SELECT id FROM sys_user WHERE username = ?"));
        assertFalse(source.contains("SELECT DISTINCT p.code FROM sys_permission"));
        assertFalse(source.contains("UPDATE sys_user SET login_ip = ?"));
    }
}
