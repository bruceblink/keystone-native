package app.keystone.auth;

import app.keystone.ApiResponse;
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
    @Inject JwtKeyRegistryService keyRegistry;
    @Inject ObjectMapper objectMapper;

    @Override
    public void filter(ContainerRequestContext context) {
        if (!(identity.getPrincipal() instanceof JsonWebToken jwt)) return;
        String accessTokenId = jwt.getClaim("jti");
        String keyId = headerClaim(jwt);
        if (keyId == null) {
            context.abortWith(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "access token signing key is not registered"));
            return;
        }
        try {
            if (!keyRegistry.accepts(keyId)) {
                context.abortWith(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "access token signing key is not registered"));
                return;
            }
        } catch (IllegalStateException e) {
            context.abortWith(ApiResponse.response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), "authorization_unavailable", "authentication state is unavailable"));
            return;
        }
        // JWT 已经通过签名校验后仍必须绑定到活动会话，缺少 jti 时直接拒绝。
        if (accessTokenId == null || accessTokenId.isBlank()) {
            context.abortWith(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "access token session identifier is required"));
            return;
        }
        String tokenType = stringClaim(jwt, "type");
        String assurance = stringClaim(jwt, "aal");
        if (!"access".equals(tokenType) || !("AAL1".equals(assurance) || "AAL2".equals(assurance))
                || JwtClaims.strings(jwt, "amr").isEmpty()) {
            context.abortWith(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "access token authentication claims are incomplete"));
            return;
        }
        String userId = claimUuid(claim(jwt, "userId"));
        long permissionVersion = claimLong(claim(jwt, "permission_version"));
        if (userId == null || permissionVersion < 0) {
            context.abortWith(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "access token permission version is required"));
            return;
        }
        try {
            if (!sessions.isAccessTokenActive(accessTokenId, userId, permissionVersion)) context.abortWith(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "session_revoked", "access session is no longer active"));
        } catch (IllegalStateException e) {
            context.abortWith(ApiResponse.response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), "authorization_unavailable", "authentication state is unavailable"));
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

    private String stringClaim(JsonWebToken jwt, String name) {
        Object value = claim(jwt, name);
        return value == null ? null : value.toString();
    }

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

    /** 从已验签令牌的原始头读取 kid；kid 不属于 JWT claims。 */
    private String headerClaim(JsonWebToken jwt) {
        try {
            String raw = jwt.getRawToken();
            if (raw == null) return null;
            String[] parts = raw.split("\\.", -1);
            if (parts.length != 3) return null;
            String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]), java.nio.charset.StandardCharsets.UTF_8);
            var node = objectMapper.readTree(header).get("kid");
            return node == null || node.isNull() ? null : node.asText();
        } catch (Exception e) {
            return null;
        }
    }
}
