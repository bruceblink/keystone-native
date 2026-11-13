package app.keystone.auth;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.security.identity.SecurityIdentity;
import org.eclipse.microprofile.jwt.JsonWebToken;

/** Rejects protected requests after their refresh session has been revoked. */
@Provider
@Priority(Priorities.AUTHENTICATION + 100)
public class AccessSessionFilter implements ContainerRequestFilter {
    @Inject SecurityIdentity identity;
    @Inject SessionRepository sessions;
    @Inject ObjectMapper objectMapper;

    @Override
    public void filter(ContainerRequestContext context) {
        if (!(identity.getPrincipal() instanceof JsonWebToken jwt)) return;
        String accessTokenId = jwt.getClaim("jti");
        // JWT 已经通过签名校验后仍必须绑定到活动会话，缺少 jti 时直接拒绝。
        if (accessTokenId == null || accessTokenId.isBlank()) {
            context.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("access token session identifier is required").build());
            return;
        }
        String userId = claimUuid(claim(jwt, "userId"));
        long permissionVersion = claimLong(claim(jwt, "permission_version"));
        if (userId == null || permissionVersion < 0) {
            context.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("access token permission version is required").build());
            return;
        }
        try {
            if (!sessions.isAccessTokenActive(accessTokenId, userId, permissionVersion)) context.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("access session is no longer active").build());
        } catch (IllegalStateException e) {
            context.abortWith(Response.status(Response.Status.SERVICE_UNAVAILABLE).entity("authentication state is unavailable").build());
        }
    }

    /** JWT 库可能把整数声明还原为不同 Number 类型，统一转换后再查询数据库。 */
    private static String claimUuid(Object value) {
        if (!(value instanceof String text)) return null;
        try { return app.keystone.identity.UuidValues.requireCanonical(text); }
        catch (IllegalArgumentException e) { return null; }
    }
    private static long claimLong(Object value) { return value instanceof Number number ? number.longValue() : value instanceof String text ? parse(text) : -1; }
    private static long parse(String value) { try { return Long.parseLong(value); } catch (NumberFormatException e) { return -1; } }

    private Object claim(JsonWebToken jwt, String name) {
        Object value = jwt.getClaim(name);
        if (value instanceof Number || value instanceof String) return value;
        try {
            String raw = jwt.getRawToken();
            if (raw == null) return null;
            String[] parts = raw.split("\\.", -1);
            if (parts.length != 3) return null;
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
            var node = objectMapper.readTree(payload).get(name);
            if (node == null || node.isNull()) return null;
            return node.isNumber() ? node.numberValue() : node.asText();
        } catch (Exception e) {
            return null;
        }
    }
}
