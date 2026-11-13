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
        assertError(new BadRequestException("invalid body"), 400, "validation_failed");
        assertError(new NotFoundException("missing record"), 404, "validation_failed");
        assertError(new NotAuthorizedException("login required"), 401, "invalid_credential");
        assertError(new ForbiddenException("permission denied"), 403, "permission_denied");
        assertError(new ServiceUnavailableException("database unavailable"), 503, "authorization_unavailable");
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
