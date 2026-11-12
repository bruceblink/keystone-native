package app.keystone.user;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.util.Set;

/** 验证密码长度、字符组成、用户名关联和配置边界。 */
class PasswordPolicyTest {
    private final PasswordPolicy policy = new PasswordPolicy(12, true, true, true, true,
            Set.of("password", "password1", "1234567890", "qwerty123", "admin"));

    @Test
    void acceptsStrongPasswordAndRejectsWeakRules() {
        assertDoesNotThrow(() -> policy.validate("alice", "S3cure!Passw0rd"));
        assertThrows(IllegalArgumentException.class, () -> policy.validate("alice", "short1!A"));
        assertThrows(IllegalArgumentException.class, () -> policy.validate("alice", "alllowercase123!"));
        assertThrows(IllegalArgumentException.class, () -> policy.validate("alice", "NoDigits!Password"));
        assertThrows(IllegalArgumentException.class, () -> policy.validate("alice", "Alice!23456789"));
    }

    @Test
    void rejectsConfigurationOutsideSafeBounds() {
        var invalid = new PasswordPolicy(7, true, true, true, true, Set.of());
        assertThrows(IllegalStateException.class, () -> invalid.validate("alice", "S3cure!Passw0rd"));
    }
}
