package app.keystone;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 校验业务错误码目录可反查且每个代码只对应一个目录项。 */
class ErrorCodeCatalogTest {
    @Test
    void everyCodeIsUniqueAndHasOperationalMetadata() {
        var values = ErrorCode.values();
        Set<String> codes = Arrays.stream(values).map(ErrorCode::code).collect(Collectors.toSet());

        assertEquals(values.length, codes.size());
        for (ErrorCode code : values) {
            assertEquals(code, ErrorCode.fromCode(code.code()));
            assertTrue(code.httpStatus() >= 400 && code.httpStatus() <= 599);
            assertNotNull(code.meaning());
            assertFalse(code.meaning().isBlank());
            assertNotNull(code.retryAdvice());
            assertFalse(code.retryAdvice().key().isBlank());
            assertNotNull(code.messageKey());
            assertTrue(code.messageKey().startsWith("error."));
        }
    }

    @Test
    void keyBusinessConditionsHaveDedicatedCodes() {
        assertEquals("active_session_conflict", ErrorCode.ACTIVE_SESSION_CONFLICT.code());
        assertEquals("mfa_required", ErrorCode.MFA_REQUIRED.code());
        assertEquals("mfa_challenge_invalid", ErrorCode.MFA_CHALLENGE_INVALID.code());
        assertEquals("rate_limited", ErrorCode.RATE_LIMITED.code());
        assertEquals("resource_not_found", ErrorCode.RESOURCE_NOT_FOUND.code());
        assertEquals("resource_conflict", ErrorCode.RESOURCE_CONFLICT.code());
        assertEquals("api_key_name_invalid", ErrorCode.API_KEY_NAME_INVALID.code());
        assertEquals("api_key_expiry_invalid", ErrorCode.API_KEY_EXPIRY_INVALID.code());
        assertEquals("api_key_expiry_out_of_range", ErrorCode.API_KEY_EXPIRY_OUT_OF_RANGE.code());
        assertEquals(422, ErrorCode.API_KEY_NAME_INVALID.httpStatus());
        assertEquals(422, ErrorCode.API_KEY_EXPIRY_INVALID.httpStatus());
        assertEquals(422, ErrorCode.API_KEY_EXPIRY_OUT_OF_RANGE.httpStatus());
        assertEquals("role_has_members", ErrorCode.ROLE_HAS_MEMBERS.code());
        assertEquals(422, ErrorCode.ROLE_HAS_MEMBERS.httpStatus());
        assertEquals("role_protected", ErrorCode.ROLE_PROTECTED.code());
        assertEquals(422, ErrorCode.ROLE_PROTECTED.httpStatus());
    }

    @Test
    void lookupDistinguishesRegisteredAndUnknownCodes() {
        assertEquals(ErrorCode.ACTIVE_SESSION_CONFLICT,
                ErrorCode.find(" active_session_conflict ").orElseThrow());
        assertTrue(ErrorCode.find("unknown_code").isEmpty());
        assertTrue(ErrorCode.find(null).isEmpty());
        assertTrue(ErrorCode.find(" ").isEmpty());
    }
}
