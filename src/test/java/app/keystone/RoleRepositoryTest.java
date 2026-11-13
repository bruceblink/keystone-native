package app.keystone;

import app.keystone.role.RoleRepository;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@QuarkusTest
class RoleRepositoryTest {
    @Inject RoleRepository roles;

    @Test
    void duplicatePermissionsAreStoredOnceAndCanBeRevoked() {
        String code = "TEST_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        try {
            roles.create(code, "Test role");
            roles.assignPermissions(code, java.util.List.of("user:read", "user:read", "role:read"));
            assertEquals(java.util.List.of("role:read", "user:read"), roles.findByCode(code).permissions());

            roles.assignPermissions(code, java.util.List.of());
            assertEquals(java.util.List.of(), roles.findByCode(code).permissions());
        } finally {
            roles.delete(code);
        }
    }

    @Test
    void roleDeletionDoesNotUseRoleNameBypass() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/role/RoleRepository.java"));
        assertFalse(source.contains("equalsIgnoreCase(\"ADMIN\")"));
        assertFalse(source.contains("equalsIgnoreCase(\"USER\")"));
    }
}
