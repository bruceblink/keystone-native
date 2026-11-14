package app.keystone;

import jakarta.annotation.Priority;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/** 将资源层抛出的 JAX-RS 异常转换为统一的 API 错误结构。 */
@Provider
@Priority(1)
public class ApiExceptionMapper implements ExceptionMapper<WebApplicationException> {
    @Override
    public Response toResponse(WebApplicationException exception) {
        Response original = exception.getResponse();
        int status = original == null ? Response.Status.INTERNAL_SERVER_ERROR.getStatusCode() : original.getStatus();
        // 统一把请求结构和字段校验归类为 422，避免资源入口各自返回不同状态码。
        if (status == Response.Status.BAD_REQUEST.getStatusCode()) {
            status = 422;
        }
        String code = errorCode(status);
        String message = message(exception, status);
        Response.ResponseBuilder builder = original == null ? Response.status(status) : Response.fromResponse(original).status(status);
        return builder.type(MediaType.APPLICATION_JSON).entity(ApiResponse.error(code, message)).build();
    }

    private static String errorCode(int status) {
        return switch (status) {
            case 401 -> "invalid_credential";
            case 403 -> "permission_denied";
            case 503 -> "authorization_unavailable";
            default -> "validation_failed";
        };
    }

    private static String message(WebApplicationException exception, int status) {
        String value = exception.getMessage();
        if (value != null && !value.isBlank() && value.length() <= 255) return value;
        return switch (status) {
            case 401 -> "authentication is required";
            case 403 -> "permission denied";
            case 404 -> "resource not found";
            case 503 -> "service is unavailable";
            default -> "request is invalid";
        };
    }
}
