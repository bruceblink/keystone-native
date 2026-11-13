package app.keystone;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

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

    @Test
    void contentMigrationUsesBinaryIdsAndGuardedReplay() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V48__notice_config_dictionary_identity_uuid.sql"));
        assertTrue(sql.contains("sys_uuid_content_migration"));
        assertTrue(sql.contains("@uuid_content_should_rebuild"));
        assertTrue(sql.contains("sys_config"));
        assertTrue(sql.contains("sys_notice"));
        assertTrue(sql.contains("sys_dict_type"));
        assertTrue(sql.contains("sys_dict_item"));
        assertTrue(sql.contains("type_id BINARY(16)"));
        assertTrue(sql.contains("UUID_TO_BIN"));
        assertTrue(sql.contains("BIN_TO_UUID"));
        assertTrue(sql.contains("INSERT IGNORE INTO sys_uuid_content_migration"));
    }

    @Test
    void jobLogAndAuditMigrationUsesBinaryIdsAndGuardedReplay() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V49__job_log_audit_identity_uuid.sql"));
        assertTrue(sql.contains("sys_uuid_job_log_migration"));
        assertTrue(sql.contains("@uuid_job_log_should_rebuild"));
        assertTrue(sql.contains("sys_job"));
        assertTrue(sql.contains("sys_job_log"));
        assertTrue(sql.contains("sys_login_log"));
        assertTrue(sql.contains("sys_operation_log"));
        assertTrue(sql.contains("sys_security_event"));
        assertTrue(sql.contains("sys_refresh_token_event"));
        assertTrue(sql.contains("id BINARY(16)"));
        assertTrue(sql.contains("token_id BINARY(16)"));
        assertTrue(sql.contains("UUID_TO_BIN"));
        assertTrue(sql.contains("INSERT IGNORE INTO sys_uuid_job_log_migration"));
    }

    @Test
    void authIdentityMigrationUsesBinaryUuidIdsAndGuardedReplay() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V50__auth_identity_binary_uuid.sql"));
        assertTrue(sql.contains("sys_uuid_auth_identity_migration"));
        assertTrue(sql.contains("@uuid_auth_should_rebuild"));
        assertTrue(sql.contains("sys_auth_session"));
        assertTrue(sql.contains("sys_refresh_token"));
        assertTrue(sql.contains("sys_service_subject"));
        assertTrue(sql.contains("sys_api_key"));
        assertTrue(sql.contains("sys_user_mfa"));
        assertTrue(sql.contains("sys_mfa_recovery_code"));
        assertTrue(sql.contains("sys_auth_challenge"));
        assertTrue(sql.contains("session_id BINARY(16)"));
        assertTrue(sql.contains("refresh_family_id BINARY(16)"));
        assertTrue(sql.contains("UUID_TO_BIN"));
        assertTrue(sql.contains("BIN_TO_UUID"));
        assertTrue(sql.contains("INSERT IGNORE INTO sys_uuid_auth_identity_migration"));
    }

    @Test
    void authenticationBusinessIdsUseUuidV7Generator() throws Exception {
        try (var files = Files.walk(Path.of("src/main/java/app/keystone/auth"))) {
            files.filter(path -> path.toString().endsWith(".java")).forEach(path -> {
                try {
                    assertFalse(Files.readString(path).contains("UUID.randomUUID()"), path.toString());
                } catch (java.io.IOException e) {
                    throw new IllegalStateException("Could not inspect " + path, e);
                }
            });
        }
    }
}
