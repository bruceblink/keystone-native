package app.keystone.auth;

import app.keystone.identity.UuidValues;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 校验 Native 权限目录与跨项目固定 UUIDv5 目录保持一致。 */
class PermissionCatalogMigrationTest {
    private static final Pattern SEED_ROW = Pattern.compile(
            "UUID_TO_BIN\\('([^']+)', 0\\), '([^']+)',");
    private static final Pattern ANNOTATION = Pattern.compile("@RequiresPermission\\(\\\"([^\\\"]+)\\\"\\)");

    private static final Set<String> EXPECTED_PERMISSIONS = Set.of(("""
            api-key:create api-key:read api-key:revoke api-key:rotate
            audit:delete audit:export audit:read cache:refresh
            config:create config:read config:refresh config:update
            department:create department:delete department:read department:update
            dictionary:create dictionary:delete dictionary:read dictionary:refresh dictionary:update
            file:read file:write
            job:create job:delete job:read job:run job:update job:update-status
            login-log:delete login-log:export login-log:read
            menu:create menu:delete menu:manage menu:read menu:update
            mfa:manage
            notice:create notice:delete notice:read notice:update
            online-session:read online-session:revoke
            operation-log:delete operation-log:export operation-log:read
            permission:manage permission:read
            post:create post:delete post:export post:read post:update
            role:assign role:create role:delete role:export role:manage role:read role:update
            server:read session:read session:revoke
            user:create user:delete user:export user:import user:read user:reset-password user:update
            """).trim().split("\\s+"));

    @Test
    void migrationSeedsEveryCanonicalPermissionWithItsUuidV5() throws Exception {
        String migration = Files.readString(Path.of(
                "src/main/resources/db/migration/V45__permission_catalog_uuid.sql"));
        Matcher matcher = SEED_ROW.matcher(migration);
        Map<String, String> vectors = new HashMap<>();
        while (matcher.find()) vectors.put(matcher.group(2), matcher.group(1));

        assertEquals(EXPECTED_PERMISSIONS, vectors.keySet());
        assertEquals(EXPECTED_PERMISSIONS.size(), vectors.size());
        vectors.forEach((permission, id) -> assertEquals(UuidValues.permissionId(permission), id));
    }

    @Test
    void migrationUsesBinaryPermissionForeignKeysAndNoLegacyPermissionSource() throws Exception {
        String migration = Files.readString(Path.of(
                "src/main/resources/db/migration/V45__permission_catalog_uuid.sql"));

        assertTrue(migration.contains("permission_id BINARY(16) NOT NULL"));
        assertTrue(migration.contains("CREATE TABLE sys_menu_permission"));
        assertTrue(migration.contains("fk_menu_permission_permission"));
        assertFalse(migration.contains("session:logout"));
        assertFalse(migration.matches("(?s).*'[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]+'.*"));
        assertFalse(migration.contains("sys_menu.permission"));
    }

    @Test
    void runtimeCatalogAndProductionAnnotationsUseOnlyCanonicalPermissions() throws Exception {
        assertEquals(EXPECTED_PERMISSIONS, PermissionCatalog.values());
        try (var files = Files.walk(Path.of("src/main/java"))) {
            files.filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !path.toString().contains("/compat/"))
                    .filter(path -> !path.getFileName().toString().startsWith("Legacy"))
                    .filter(path -> !path.getFileName().toString().equals("PermissionInterceptor.java"))
                    .filter(path -> !path.getFileName().toString().contains("Compatibility"))
                    .forEach(path -> {
                        try {
                            var matcher = ANNOTATION.matcher(Files.readString(path));
                            while (matcher.find()) assertTrue(PermissionCatalog.contains(matcher.group(1)), path + " has unknown permission");
                        } catch (java.io.IOException e) {
                            throw new IllegalStateException("Could not inspect " + path, e);
                        }
                    });
        }
        assertFalse(PermissionCatalog.contains("user:write"));
        assertFalse(PermissionCatalog.contains("profile:read"));
    }
}
