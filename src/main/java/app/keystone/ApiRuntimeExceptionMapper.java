package app.keystone;

import app.keystone.auth.AuthorizationDeniedException;
import jakarta.annotation.Priority;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/** 将领域层未转换的参数和状态异常收敛为统一 API 错误结构。 */
@Provider
@Priority(2)
public class ApiRuntimeExceptionMapper implements ExceptionMapper<RuntimeException> {
    @Override
    public Response toResponse(RuntimeException exception) {
        if (exception instanceof AuthorizationDeniedException denied) {
            return response(denied.status(), denied.code(), denied.getMessage());
        }
        if (exception instanceof IllegalArgumentException || containsIllegalArgument(exception)) {
            return response(422, "validation_failed", "request is invalid");
        }
        return response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), "authorization_unavailable", "service is unavailable");
    }

    private static boolean containsIllegalArgument(Throwable error) {
        for (Throwable current = error.getCause(); current != null; current = current.getCause()) {
            if (current instanceof IllegalArgumentException) return true;
        }
        return false;
    }

    private static Response response(int status, String code, String message) {
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .entity(ApiResponse.error(code, message))
                .build();
    }
}
