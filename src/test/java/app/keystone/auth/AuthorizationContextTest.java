package app.keystone.auth;

import app.keystone.role.RoleRepository;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证业务命令不能在 REST 拦截器之外缺少主体或权限时执行。 */
@QuarkusTest
class AuthorizationContextTest {
    @Inject AuthorizationService authorization;
    @Inject RoleRepository roles;

    @Test
    void missingContextIsRejectedWithInvalidCredential() {
        AuthorizationDeniedException error = assertThrows(
                AuthorizationDeniedException.class,
                () -> authorization.require(null, "role:create", "role"));
        assertEquals("invalid_credential", error.code());
        assertEquals(401, error.status());
    }

    @Test
    void userContextWithoutPermissionCannotCallRoleCommand() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000001", "limited", "USER", Set.of(), false, false);
        assertFalse(context.isSystem());
        AuthorizationDeniedException error = assertThrows(
                AuthorizationDeniedException.class,
                () -> roles.create(context, "SHOULD_NOT_BE_WRITTEN", "Denied"));
        assertEquals("permission_denied", error.code());
        assertEquals(403, error.status());
    }

    @Test
    void forgedSystemFieldsCannotBeConstructedThroughUserFactory() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000002", "limited", "USER", Set.of("*"), true, false);
        assertFalse(context.isSystem());
        assertFalse(context.hasPermission("role:create"));
    }
}
