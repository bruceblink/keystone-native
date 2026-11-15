package app.keystone;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证新主线响应始终包含统一的 error 字段和固定错误分类。 */
class ApiResponseContractTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void successResponseContainsNullError() throws Exception {
        var response = ApiResponse.ok(java.util.Map.of("id", "value"));
        var json = mapper.readTree(mapper.writeValueAsString(response));

        assertTrue(json.get("success").asBoolean());
        assertTrue(json.has("data"));
        assertEquals("OK", json.get("message").asText());
        assertTrue(json.has("error"));
        assertTrue(json.get("error").isNull());
    }

    @Test
    void explicitCodesAreReturnedWithoutMessageClassification() {
        assertError(ErrorCode.INVALID_CREDENTIAL, "invalid credentials");
        assertError(ErrorCode.PERMISSION_DENIED, "permission denied");
        assertError(ErrorCode.DATA_SCOPE_DENIED, "data scope denied");
        assertError(ErrorCode.SESSION_REVOKED, "access session is no longer active");
        assertError(ErrorCode.AUTHORIZATION_UNAVAILABLE, "authorization state is unavailable");
        assertError(ErrorCode.VALIDATION_FAILED, "request body is required");
        assertEquals("validation_failed", ApiResponse.error("permission denied").error().get("code"));
    }

    @Test
    void explicitUnknownCategoryIsRejected() {
        var response = ApiResponse.error("old_numeric_code", "legacy error");
        assertEquals("validation_failed", response.error().get("code"));
        assertEquals("legacy error", response.message());
        assertNull(response.data());
    }

    private static void assertError(ErrorCode code, String message) {
        var response = ApiResponse.error(code, message);
        assertEquals(code.code(), response.error().get("code"));
        assertEquals(message, response.message());
        assertNull(response.data());
    }
}
