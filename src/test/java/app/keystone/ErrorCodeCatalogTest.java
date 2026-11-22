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
        assertEquals("api_key_page_changed", ErrorCode.API_KEY_PAGE_CHANGED.code());
        assertEquals(409, ErrorCode.API_KEY_PAGE_CHANGED.httpStatus());
        assertTrue(ErrorCode.API_KEY_PAGE_CHANGED.retryable());
        assertEquals(ErrorCode.API_KEY_PAGE_CHANGED,
                ErrorCode.find("api_key_page_changed").orElseThrow());
        assertEquals("password_same_as_current", ErrorCode.PASSWORD_SAME_AS_CURRENT.code());
        assertEquals("password_required", ErrorCode.PASSWORD_REQUIRED.code());
        assertEquals("password_too_short", ErrorCode.PASSWORD_TOO_SHORT.code());
        assertEquals("password_disallowed", ErrorCode.PASSWORD_DISALLOWED.code());
        assertEquals("password_contains_username", ErrorCode.PASSWORD_CONTAINS_USERNAME.code());
        assertEquals("password_missing_uppercase", ErrorCode.PASSWORD_MISSING_UPPERCASE.code());
        assertEquals("password_missing_lowercase", ErrorCode.PASSWORD_MISSING_LOWERCASE.code());
        assertEquals("password_missing_digit", ErrorCode.PASSWORD_MISSING_DIGIT.code());
        assertEquals("password_missing_special", ErrorCode.PASSWORD_MISSING_SPECIAL.code());
        assertEquals("username_already_exists", ErrorCode.USERNAME_ALREADY_EXISTS.code());
        assertEquals("username_invalid_format", ErrorCode.USERNAME_INVALID_FORMAT.code());
        assertEquals("notice_published_invalid", ErrorCode.NOTICE_PUBLISHED_INVALID.code());
        assertEquals(422, ErrorCode.USERNAME_ALREADY_EXISTS.httpStatus());
        assertEquals(422, ErrorCode.USERNAME_INVALID_FORMAT.httpStatus());
        assertEquals(422, ErrorCode.NOTICE_PUBLISHED_INVALID.httpStatus());
        assertEquals(422, ErrorCode.API_KEY_NAME_INVALID.httpStatus());
        assertEquals(422, ErrorCode.API_KEY_EXPIRY_INVALID.httpStatus());
        assertEquals(422, ErrorCode.API_KEY_EXPIRY_OUT_OF_RANGE.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_SAME_AS_CURRENT.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_REQUIRED.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_TOO_SHORT.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_DISALLOWED.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_CONTAINS_USERNAME.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_MISSING_UPPERCASE.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_MISSING_LOWERCASE.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_MISSING_DIGIT.httpStatus());
        assertEquals(422, ErrorCode.PASSWORD_MISSING_SPECIAL.httpStatus());
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
