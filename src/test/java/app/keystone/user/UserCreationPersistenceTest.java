package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户创建和角色绑定使用 ORM 事务，不重新引入手写 SQL。 */
class UserCreationPersistenceTest {
    @Test
    void userCreationDelegatesToOrmRepository() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));
        int start = source.indexOf("public User create(AuthorizationContext context");
        int end = source.indexOf("\n    private User update", start);
        String methods = source.substring(start, end);
        assertTrue(methods.contains("ormUsers.createUser"));
        assertFalse(methods.contains("prepareStatement"));
        assertFalse(methods.contains("INSERT INTO sys_user"));
    }

    @Test
    void ormCreationUsesRepositoryTransactionAndRoleLookup() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyUserRepository.java"));
        assertTrue(source.contains("createUser"));
        assertTrue(source.contains("ApiKeyRoleRepository"));
        assertTrue(source.contains("persistAndFlush"));
        assertTrue(source.contains("@Transactional"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
