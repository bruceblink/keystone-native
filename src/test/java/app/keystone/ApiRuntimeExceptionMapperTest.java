package app.keystone;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 验证领域层参数异常不会绕过统一 API 错误结构。 */
class ApiRuntimeExceptionMapperTest {
    private final ApiRuntimeExceptionMapper mapper = new ApiRuntimeExceptionMapper();

    @Test
    void mapsDirectAndWrappedInvalidArgumentsToValidationErrors() {
        assertError(new IllegalArgumentException("invalid UUID"), 422, "validation_failed");
        assertError(new IllegalStateException("Could not find user", new IllegalArgumentException("invalid UUID")),
                422, "validation_failed");
    }

    @Test
    void mapsUnexpectedStateFailuresToUnavailableErrors() {
        assertError(new IllegalStateException("database unavailable"), 503, "authorization_unavailable");
    }

    private void assertError(RuntimeException exception, int status, String code) {
        var response = mapper.toResponse(exception);
        assertEquals(status, response.getStatus());
        var body = (ApiResponse<?>) response.getEntity();
        assertEquals(code, body.error().get("code"));
    }
}
