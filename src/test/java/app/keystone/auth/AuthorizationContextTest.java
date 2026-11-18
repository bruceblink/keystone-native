package app.keystone.auth;

import app.keystone.role.RoleRepository;
import app.keystone.user.UserRepository;
import app.keystone.dept.DepartmentRepository;
import app.keystone.audit.OperationLogRepository;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** 验证业务命令不能在 REST 拦截器之外缺少主体或权限时执行。 */
@QuarkusTest
class AuthorizationContextTest {
    @Inject AuthorizationService authorization;
    @Inject RoleRepository roles;
    @Inject UserRepository users;
    @Inject DepartmentRepository departments;
    @Inject OperationLogRepository operationLogs;

    @Test
    void missingContextIsRejectedWithAuthenticationRequired() {
        AuthorizationDeniedException error = assertThrows(
                AuthorizationDeniedException.class,
                () -> authorization.require(null, "role:create", "role"));
        assertEquals("authentication_required", error.code());
        assertEquals(401, error.status());
    }

    @Test
    void userContextWithoutPermissionCannotCallRoleCommand() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000001", "limited", "USER", Set.of(), DataScopeService.Scope.none());
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
                "00000000-0000-7000-8000-000000000002", "limited", "USER", Set.of("*"), DataScopeService.Scope.unrestricted());
        assertFalse(context.isSystem());
        assertFalse(context.hasPermission("role:create"));
    }

    @Test
    void contextExposesUnifiedPrincipalFields() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000004", "limited", "PASSWORD", Set.of("role:read"),
                DataScopeService.Scope.unrestricted());
        assertEquals("USER", context.subjectType());
        assertEquals("PASSWORD", context.credentialType());
        assertEquals("web", context.clientId());
        assertEquals(Set.of("role:read"), context.approvedScopes());
        assertEquals("ALL", context.dataScope());
        assertEquals("AAL1", context.authenticationLevel());
    }

    @Test
    void explicitServicePrincipalVectorPreservesCredentialAndScopeFields() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000005", "SERVICE", "service", "API_KEY",
                "00000000-0000-7000-8000-000000000006", "api", Set.of("role:read"),
                Set.of("role:read"), "TENANT", 9, "AAL2", DataScopeService.Scope.unrestricted());
        assertEquals("SERVICE", context.subjectType());
        assertEquals("API_KEY", context.credentialType());
        assertEquals("00000000-0000-7000-8000-000000000006", context.credentialId());
        assertEquals("api", context.clientId());
        assertEquals(Set.of("role:read"), context.approvedScopes());
        assertEquals("TENANT", context.dataScope());
        assertEquals(9, context.permissionVersion());
        assertEquals("AAL2", context.authenticationLevel());
    }

    @Test
    @TestTransaction
    void apiKeyCommandRejectsPermissionOutsideApprovedScope() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000007", "SERVICE", "service", "API_KEY",
                "00000000-0000-7000-8000-000000000008", "api", Set.of("role:create", "role:read"),
                Set.of("role:read"), "ALL", 1, "AAL1", DataScopeService.Scope.unrestricted());

        assertFalse(context.hasPermission("role:create"));
        AuthorizationDeniedException error = assertThrows(
                AuthorizationDeniedException.class,
                () -> roles.create(context, "API_KEY_SCOPE_BYPASS", "Denied by key scope"));

        assertEquals("permission_denied", error.code());
        assertEquals(403, error.status());
        assertFalse(roles.list(context).stream()
                .anyMatch(role -> "API_KEY_SCOPE_BYPASS".equals(role.code())));
    }

    @Test
    void userAndDepartmentCommandsRejectOutOfScopeWritesBeforePersistence() {
        AuthorizationContext context = AuthorizationContext.user(
                "00000000-0000-7000-8000-000000000003", "limited", "USER",
                Set.of("user:create", "department:create"), DataScopeService.Scope.none());
        AuthorizationDeniedException userError = assertThrows(
                AuthorizationDeniedException.class,
                () -> users.create(context, "blocked", "Strong!123", "Blocked", null,
                        null, null, null, null, null, null, null));
        assertEquals("data_scope_denied", userError.code());
        AuthorizationDeniedException departmentError = assertThrows(
                AuthorizationDeniedException.class,
                () -> departments.create(context, "blocked-dept", "Blocked", null, 0));
        assertEquals("data_scope_denied", departmentError.code());
    }

    @Test
    void userDrivenAuditWriteRequiresAnAuthorizationContext() {
        AuthorizationDeniedException error = assertThrows(
                AuthorizationDeniedException.class,
                () -> operationLogs.record((AuthorizationContext) null, "CREATE", "user", "ignored", null));
        assertEquals("authentication_required", error.code());
    }
}
