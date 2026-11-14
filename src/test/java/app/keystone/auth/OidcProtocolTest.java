package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 OIDC 授权请求的 state、PKCE S256 和 verifier 输入边界。 */
class OidcProtocolTest {
    @Test
    void computesRfc7636S256Challenge() {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", OidcService.pkceChallenge(verifier));
    }

    @Test
    void acceptsOnlyHighEntropyProtocolValues() {
        String value = "a".repeat(43);
        assertTrue(OidcService.validState(value));
        assertTrue(OidcService.validCodeChallenge(value));
        assertTrue(OidcService.validVerifier(value));
        assertFalse(OidcService.validState("short"));
        assertFalse(OidcService.validCodeChallenge("a".repeat(42)));
        assertFalse(OidcService.validVerifier("a".repeat(43) + "="));
    }
}
