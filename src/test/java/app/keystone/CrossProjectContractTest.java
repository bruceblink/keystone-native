package app.keystone;

import app.keystone.auth.AuthResource;
import app.keystone.auth.PermissionCatalog;
import app.keystone.auth.RequiresPermission;
import app.keystone.monitor.SecurityObservabilityResource;
import app.keystone.role.RoleResource;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 固定 Native 与 Phoenix 共享的认证、权限、错误码和监控路由约定。 */
class CrossProjectContractTest {
    @Test
    void tokenResponseUsesTheSharedFieldNames() {
        Set<String> fields = recordFields(AuthResource.TokenResponse.class);

        assertEquals(Set.of("accessToken", "refreshToken", "tokenType", "expiresIn", "refreshExpiresIn",
                "username", "displayName", "roles", "sessionId", "clientId"), fields);
        assertFalse(fields.contains("token"));
        assertFalse(fields.contains("currentUser"));
    }

    @Test
    void rolePermissionAndSecurityRoutesUseCanonicalPermissions() {
        assertEquals("/v1/roles", RoleResource.class.getAnnotation(Path.class).value());
        Method permissionMethod = Arrays.stream(RoleResource.class.getDeclaredMethods())
                .filter(method -> method.isAnnotationPresent(PUT.class))
                .filter(method -> method.isAnnotationPresent(Path.class))
                .filter(method -> "/{id}/permissions".equals(method.getAnnotation(Path.class).value()))
                .findFirst()
                .orElseThrow();
        assertEquals("role:manage", permissionMethod.getAnnotation(RequiresPermission.class).value());
        assertTrue(PermissionCatalog.contains("user:read"));
        assertTrue(PermissionCatalog.values().stream().allMatch(permission -> permission.matches("[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*")));
        assertFalse(PermissionCatalog.contains("menu.user.read"));

        assertEquals("/v1/monitor/security", SecurityObservabilityResource.class.getAnnotation(Path.class).value());
        Method reportMethod = Arrays.stream(SecurityObservabilityResource.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("report"))
                .findFirst()
                .orElseThrow();
        assertNotNull(reportMethod.getAnnotation(jakarta.ws.rs.GET.class));
        assertEquals("/report", reportMethod.getAnnotation(Path.class).value());
        assertEquals("audit:read", reportMethod.getAnnotation(RequiresPermission.class).value());
    }

    @Test
    void errorCodesUseTheSharedCatalog() {
        assertEquals("permission_denied", ApiResponse.error(ErrorCode.PERMISSION_DENIED, "permission denied").error().get("code"));
        assertEquals("data_scope_denied", ApiResponse.error(ErrorCode.DATA_SCOPE_DENIED, "data scope denied").error().get("code"));
        assertEquals("validation_failed", ApiResponse.error(ErrorCode.VALIDATION_FAILED, "request body is required").error().get("code"));
        assertTrue(ErrorCode.isRegistered("active_session_conflict"));
        assertTrue(ErrorCode.isRegistered("mfa_required"));
    }

    private static Set<String> recordFields(Class<?> recordType) {
        return Arrays.stream(recordType.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName)
                .collect(Collectors.toUnmodifiableSet());
    }
}
