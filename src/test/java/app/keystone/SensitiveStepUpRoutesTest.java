package app.keystone;

import app.keystone.auth.RequiresMfaStepUp;
import app.keystone.compat.LegacyRoleResource;
import app.keystone.compat.LegacyUserResource;
import app.keystone.monitor.MonitorResource;
import app.keystone.profile.ProfileResource;
import app.keystone.role.RoleResource;
import app.keystone.user.UserResource;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/** 检查敏感写操作声明了统一的 MFA step-up 边界。 */
class SensitiveStepUpRoutesTest {
    @Test
    void modernSensitiveRoutesRequireStepUp() throws Exception {
        assertAnnotated(RoleResource.class, "create", RoleResource.RoleRequest.class);
        assertAnnotated(RoleResource.class, "update", String.class, RoleResource.RoleRequest.class);
        assertAnnotated(RoleResource.class, "permissions", String.class, RoleResource.PermissionRequest.class);
        assertAnnotated(RoleResource.class, "delete", String.class);

        assertAnnotated(UserResource.class, "create", UserResource.UserRequest.class);
        assertAnnotated(UserResource.class, "update", long.class, UserResource.UserRequest.class);
        assertAnnotated(UserResource.class, "password", long.class, UserResource.PasswordRequest.class);
        assertAnnotated(UserResource.class, "status", long.class, UserResource.StatusRequest.class);
        assertAnnotated(UserResource.class, "delete", long.class);
        assertAnnotated(UserResource.class, "deleteBatch", String.class);

        assertAnnotated(ProfileResource.class, "password", ProfileResource.PasswordRequest.class);
        assertAnnotated(MonitorResource.class, "logout", long.class);
    }

    @Test
    void compatibilitySensitiveRoutesRequireStepUp() throws Exception {
        assertAnnotated(LegacyRoleResource.class, "create", LegacyRoleResource.RoleCommand.class);
        assertAnnotated(LegacyRoleResource.class, "update", LegacyRoleResource.RoleCommand.class);
        assertAnnotated(LegacyRoleResource.class, "delete", String.class);
        assertAnnotated(LegacyRoleResource.class, "status", long.class, LegacyRoleResource.StatusCommand.class);
        assertAnnotated(LegacyRoleResource.class, "dataScope", long.class, LegacyRoleResource.DataScopeCommand.class);
        assertAnnotated(LegacyRoleResource.class, "grant", long.class, String.class);
        assertAnnotated(LegacyRoleResource.class, "revoke", Long.class, String.class);

        assertAnnotated(LegacyUserResource.class, "importCsv", org.jboss.resteasy.reactive.multipart.FileUpload.class);
        assertAnnotated(LegacyUserResource.class, "create", LegacyUserResource.UserCommand.class);
        assertAnnotated(LegacyUserResource.class, "update", long.class, LegacyUserResource.UserCommand.class);
        assertAnnotated(LegacyUserResource.class, "delete", String.class);
        assertAnnotated(LegacyUserResource.class, "password", long.class, LegacyUserResource.PasswordCommand.class);
        assertAnnotated(LegacyUserResource.class, "status", long.class, LegacyUserResource.StatusCommand.class);

        assertAnnotated(app.keystone.compat.LegacyProfileResource.class, "password", ProfileResource.PasswordRequest.class);
    }

    private static void assertAnnotated(Class<?> type, String name, Class<?>... parameterTypes) throws Exception {
        Method method = type.getDeclaredMethod(name, parameterTypes);
        assertNotNull(method.getAnnotation(RequiresMfaStepUp.class), type.getSimpleName() + "." + name);
    }
}
