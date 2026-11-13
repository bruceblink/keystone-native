package app.keystone;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 UUID 核心迁移包含二进制边界和成功重跑保护。 */
class UuidIdentityMigrationTest {
    @Test
    void migrationRebuildsBinaryIdentityAndGuardsCompletedRuns() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V46__uuid_identity_core.sql"));
        assertTrue(sql.contains("sys_uuid_identity_migration"));
        assertTrue(sql.contains("@uuid_identity_should_rebuild"));
        assertTrue(sql.contains("IF(@uuid_identity_should_rebuild = 1"));
        assertTrue(sql.contains("BINARY(16)"));
        assertTrue(sql.contains("post_id BIGINT"));
        assertTrue(sql.contains("UUID_TO_BIN"));
        assertTrue(sql.contains("BIN_TO_UUID"));
        assertTrue(sql.contains("INSERT IGNORE INTO sys_uuid_identity_migration"));
    }

    @Test
    void postAndMenuMigrationUsesBinaryIdsAndGuardedReplay() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V47__post_menu_identity_uuid.sql"));
        assertTrue(sql.contains("sys_uuid_menu_post_migration"));
        assertTrue(sql.contains("@uuid_menu_post_should_rebuild"));
        assertTrue(sql.contains("sys_user DROP INDEX idx_user_post"));
        assertTrue(sql.contains("post_id BINARY(16)"));
        assertTrue(sql.contains("fk_user_post"));
        assertTrue(sql.contains("menu_id BINARY(16)"));
        assertTrue(sql.contains("parent_id BINARY(16)"));
        assertTrue(sql.contains("UUID_TO_BIN"));
        assertTrue(sql.contains("INSERT INTO sys_uuid_menu_post_migration"));
    }
}
