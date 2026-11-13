package app.keystone.audit;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityEventRepositoryTest {
    @Test
    void migrationDefinesBoundaryEventStorageWithNonSecretCredentialIdentity() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V43__security_events.sql"));
        String extension = Files.readString(Path.of("src/main/resources/db/migration/V44__security_event_credential_id.sql"));
        assertTrue(sql.contains("CREATE TABLE IF NOT EXISTS sys_security_event"));
        assertTrue(sql.contains("event_type VARCHAR(32)"));
        assertTrue(sql.contains("outcome VARCHAR(32)"));
        assertTrue(!sql.contains("token") && !sql.contains("password") && !sql.contains("api_key"));
        assertTrue(extension.contains("credential_id VARCHAR(128)"));
        assertTrue(extension.contains("idx_security_event_credential_time"));
    }
}
