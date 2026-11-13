package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证 JWT 启动配置的关键失败边界。 */
class JwtConfigurationStartupCheckTest {
    @Test
    void rejectsMissingKeyLocations() {
        assertThrows(IllegalStateException.class,
                () -> JwtConfigurationStartupCheck.requireReadable("JWT public key", ""));
    }

    @Test
    void rejectsOverlappingKeysWhenVerifierStillUsesPublishingPem() {
        assertThrows(IllegalStateException.class,
                () -> JwtConfigurationStartupCheck.requireOverlappingVerificationKey(
                        "keys/publicKey.pem", "keys/publicKey.pem", 2));
    }

    @Test
    void acceptsHttpsJwkSetForOverlappingKeys() {
        assertDoesNotThrow(() -> JwtConfigurationStartupCheck.requireOverlappingVerificationKey(
                "https://auth.example.test/api/.well-known/jwks.json", "keys/publicKey.pem", 2));
    }

    @Test
    void acceptsLocalJwkSetForOverlappingKeys() throws Exception {
        Path jwks = Files.createTempFile("keystone-jwks-", ".json");
        try {
            Files.writeString(jwks, "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"current\",\"alg\":\"RS256\"}]}");
            assertDoesNotThrow(() -> JwtConfigurationStartupCheck.requireOverlappingVerificationKey(
                    jwks.toString(), "keys/publicKey.pem", 2));
        } finally {
            Files.deleteIfExists(jwks);
        }
    }
}
