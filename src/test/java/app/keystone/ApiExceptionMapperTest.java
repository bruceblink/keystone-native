package app.keystone;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.ServiceUnavailableException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 JAX-RS 异常统一返回 success/data/message/error 字段。 */
class ApiExceptionMapperTest {
    private final ApiExceptionMapper mapper = new ApiExceptionMapper();

    @Test
    void mapsCommonHttpExceptionsToCanonicalErrorCodes() {
        assertError(new BadRequestException("invalid body"), 422, "validation_failed");
        assertError(new NotFoundException("missing record"), 404, "resource_not_found");
        assertError(new NotAuthorizedException("login required"), 401, "invalid_credential");
        assertError(new ForbiddenException("permission denied"), 403, "permission_denied");
        assertError(new ServiceUnavailableException("database unavailable"), 503, "service_unavailable");
    }

    @Test
    void preservesExplicitCodeFromOriginalResponse() {
        var exception = new NotAuthorizedException(ApiResponse.response(401, ErrorCode.AUTHENTICATION_REQUIRED,
                "authentication is required"));
        assertError(exception, 401, "authentication_required");
    }

    private void assertError(jakarta.ws.rs.WebApplicationException exception, int status, String code) {
        var response = mapper.toResponse(exception);
        assertEquals(status, response.getStatus());
        assertTrue(response.getEntity() instanceof ApiResponse<?>);
        var body = (ApiResponse<?>) response.getEntity();
        assertEquals(false, body.success());
        assertEquals(code, body.error().get("code"));
    }
}
