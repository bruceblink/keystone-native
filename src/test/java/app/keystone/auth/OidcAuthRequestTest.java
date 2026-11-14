package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 OIDC 状态记录保存服务端 verifier，并且实体只能被一次消费。 */
class OidcAuthRequestTest {
    @Test
    void consumesVerifierOnceBeforeProviderExchange() throws Exception {
        Instant expiry = Instant.parse("2030-01-01T00:05:00Z");
        var request = new OidcAuthRequestEntity("state", "nonce", "challenge", "verifier", "client", "https://app.example/callback", expiry);
        assertEquals("verifier", request.codeVerifier());
        assertEquals(expiry, request.expiresAt());
        request.consume(Instant.parse("2030-01-01T00:01:00Z"));
        assertNotNull(request.consumedAt());
        assertTrue(request.consumedAt().isBefore(expiry));
    }

    @Test
    void migrationKeepsVerifierAndExpiryInTheShortLivedRecord() throws Exception {
        String sql = Files.readString(Path.of("src/main/resources/db/migration/V53__oidc_identity_mapping.sql"));
        assertTrue(sql.contains("expires_at TIMESTAMP(6) NOT NULL"));
        assertTrue(sql.contains("consumed_at TIMESTAMP(6) NULL"));
        String verifierSql = Files.readString(Path.of("src/main/resources/db/migration/V54__oidc_pkce_verifier.sql"));
        assertTrue(verifierSql.contains("code_verifier VARCHAR(128) NOT NULL"));
    }
}
