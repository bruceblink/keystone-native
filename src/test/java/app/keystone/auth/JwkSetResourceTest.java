package app.keystone.auth;

import jakarta.ws.rs.Path;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 验证 JWK Set 的公开发现路径。 */
class JwkSetResourceTest {
    @Test
    void exposesWellKnownPath() {
        assertEquals("/.well-known/jwks.json", JwkSetResource.class.getAnnotation(Path.class).value());
    }
}
