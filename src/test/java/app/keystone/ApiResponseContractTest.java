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
    void errorMessagesMapToTheSixFixedCategories() {
        assertError("invalid credentials", "invalid_credential");
        assertError("permission denied", "permission_denied");
        assertError("data scope denied", "data_scope_denied");
        assertError("access session is no longer active", "session_revoked");
        assertError("authorization state is unavailable", "authorization_unavailable");
        assertError("request body is required", "validation_failed");
    }

    @Test
    void explicitUnknownCategoryIsRejected() {
        var response = ApiResponse.error("old_numeric_code", "legacy error");
        assertEquals("validation_failed", response.error());
        assertEquals("legacy error", response.message());
        assertNull(response.data());
    }

    private static void assertError(String message, String category) {
        var response = ApiResponse.error(message);
        assertEquals(category, response.error());
        assertEquals(message, response.message());
        assertNull(response.data());
    }
}
