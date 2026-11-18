package app.keystone.user;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    void reportsOneStableCodeForEachPolicyFailureInExistingShortCircuitOrder() {
        assertCode(policy, "alice", null, app.keystone.ErrorCode.PASSWORD_REQUIRED);
        assertCode(policy, "alice", "Short1!", app.keystone.ErrorCode.PASSWORD_TOO_SHORT);

        var strict = new PasswordPolicy(8, true, true, true, true, Set.of("forbidden123!"));
        assertCode(strict, "nobody", "forbidden123!", app.keystone.ErrorCode.PASSWORD_DISALLOWED);
        assertCode(strict, "AliceUser", "AliceUser!123", app.keystone.ErrorCode.PASSWORD_CONTAINS_USERNAME);
        assertCode(strict, "nobody", "lowercase123!", app.keystone.ErrorCode.PASSWORD_MISSING_UPPERCASE);
        assertCode(strict, "nobody", "UPPERCASE123!", app.keystone.ErrorCode.PASSWORD_MISSING_LOWERCASE);
        assertCode(strict, "nobody", "NoDigitsHere!!", app.keystone.ErrorCode.PASSWORD_MISSING_DIGIT);
        assertCode(strict, "nobody", "NoSpecial1234", app.keystone.ErrorCode.PASSWORD_MISSING_SPECIAL);

        var order = new PasswordPolicy(8, true, true, true, true, Set.of("AliceUser!123"));
        assertCode(order, "AliceUser", "AliceUser!123", app.keystone.ErrorCode.PASSWORD_DISALLOWED);
    }

    private static void assertCode(PasswordPolicy policy, String username, String password,
                                   app.keystone.ErrorCode expected) {
        PasswordPolicyException error = assertThrows(PasswordPolicyException.class,
                () -> policy.validate(username, password));
        assertEquals(expected, error.errorCode());
        assertEquals("password does not meet security policy", error.getMessage());
    }
}
