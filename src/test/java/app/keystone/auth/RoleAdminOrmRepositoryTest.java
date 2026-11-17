package app.keystone.auth;

import app.keystone.role.ProtectedSystemRoleException;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RoleAdminOrmRepositoryTest {
    /** 非固定 UUID 的 ADMIN 角色即使没有成员查询结果也始终受保护。 */
    @Test
    void adminCodeIsProtectedIndependentOfIdAndMembers() {
        ApiKeyRoleEntity role = new ApiKeyRoleEntity("aDmIn", "Custom display name");
        assertNotEquals(UUID.fromString("2f57b9e0-836d-5f15-97a3-d4be27dc0bef"), role.uuid());

        assertThrows(ProtectedSystemRoleException.class,
                () -> RoleAdminOrmRepository.ensureNotSystemAdmin(role));
    }

    /** 保护规则只检查角色代码，不把任意用户自定义代码或显示名称当作系统角色。 */
    @Test
    void customRoleCodeAndDisplayNameAreNotProtected() {
        ApiKeyRoleEntity role = new ApiKeyRoleEntity("CUSTOM_ADMIN", "Administrator");
        assertDoesNotThrow(() -> RoleAdminOrmRepository.ensureNotSystemAdmin(role));
    }
}
