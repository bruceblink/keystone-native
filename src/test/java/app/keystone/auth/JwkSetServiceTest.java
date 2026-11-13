package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 JWK 字段、RSA 公钥转换和失败关闭边界。 */
class JwkSetServiceTest {
    @Test
    void publishesRsaJwkWithoutPrivateKeyMaterial() {
        var set = new JwkSetService("keys/publicKey.pem", "test-rs256-1").current();
        assertEquals(1, set.keys().size());
        var key = set.keys().get(0);
        assertEquals("RSA", key.kty());
        assertEquals("test-rs256-1", key.kid());
        assertEquals("RS256", key.alg());
        assertEquals("sig", key.use());
        assertEquals("AQAB", key.e());
        assertTrue(key.n().matches("[A-Za-z0-9_-]+"));
        assertTrue(key.e().matches("[A-Za-z0-9_-]+"));
    }

    @Test
    void rejectsMissingKeyLocationAndUnsafeKeyId() {
        assertThrows(IllegalStateException.class, () -> new JwkSetService("", "test-rs256-1").current());
        assertThrows(IllegalStateException.class, () -> new JwkSetService("keys/publicKey.pem", "../private"));
    }

    @Test
    void doesNotReadPrivateKeyAsPublicKey() {
        assertThrows(IllegalStateException.class,
                () -> new JwkSetService("keys/privateKey.pem", "test-rs256-1").current());
    }

    @Test
    void publishesConfiguredOverlappingKeys() throws Exception {
        Path key = Files.createTempFile("keystone-jwk-overlap-", ".pem");
        try {
            Files.writeString(key, Files.readString(Path.of("src/test/resources/keys/publicKey.pem")));
            var service = new JwkSetService("keys/publicKey.pem", "current", 60, "old=" + key);
            assertEquals(2, service.current().keys().size());
            assertEquals("current", service.current().keys().get(0).kid());
            assertEquals("old", service.current().keys().get(1).kid());
        } finally {
            Files.deleteIfExists(key);
        }
    }

    @Test
    void rejectsDuplicateOverlappingKeyIds() {
        assertThrows(IllegalArgumentException.class,
                () -> new JwkSetService("keys/publicKey.pem", "current", 60, "current=keys/publicKey.pem"));
    }

    @Test
    void keepsOneValidatedSnapshotForJwkAndPemReaders() throws Exception {
        Path key = Files.createTempFile("keystone-jwk-", ".pem");
        try {
            Files.writeString(key, Files.readString(Path.of("src/test/resources/keys/publicKey.pem")));
            var service = new JwkSetService(key.toString(), "test-rs256-1", 60);
            var first = service.current();
            var pem = service.currentPem();
            Files.delete(key);
            assertEquals(first, service.current());
            assertEquals(pem, service.currentPem());
        } finally {
            Files.deleteIfExists(key);
        }
    }
}
