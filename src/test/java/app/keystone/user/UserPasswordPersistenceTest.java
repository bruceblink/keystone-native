package app.keystone.user;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证独立密码修改路径使用 ORM 行锁和凭据状态更新。 */
class UserPasswordPersistenceTest {
    @Test
    void passwordOnlyUpdatesDelegateToOrm() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/user/UserRepository.java"));
        int start = source.indexOf("public User update(long id");
        int end = source.indexOf("\n    public User updateExtended", start);
        String method = source.substring(start, end);
        assertTrue(method.contains("ormUsers.updatePassword(id, password, passwordPolicy)"));
        assertFalse(method.contains("password_hash = ?"));
    }

    @Test
    void ormPasswordUpdateUsesWriteLockAndBcrypt() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyUserRepository.java"));
        assertTrue(source.contains("updatePassword"));
        assertTrue(source.contains("PESSIMISTIC_WRITE"));
        assertTrue(source.contains("BcryptUtil.bcryptHash"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
