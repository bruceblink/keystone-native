package app.keystone.audit;

import app.keystone.identity.UuidValues;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;
import org.eclipse.microprofile.jwt.JsonWebToken;

/** 从当前安全身份和请求读取可审计的上下文，不读取或保存秘密凭据。 */
public final class SecurityEventContext {
    private SecurityEventContext() {
    }

    public static SecurityEventRepository.Context from(SecurityIdentity identity, RoutingContext routingContext) {
        String sessionId = null;
        String scope = null;
        if (identity != null && !identity.isAnonymous()) {
            Object attributeSession = identity.getAttribute("sessionId");
            Object attributeScope = identity.getAttribute("scopes");
            if (attributeSession != null) sessionId = canonicalUuid(attributeSession.toString());
            scope = scopeText(attributeScope);
            if (identity.getPrincipal() instanceof JsonWebToken jwt) {
                if (sessionId == null) sessionId = canonicalUuid(textClaim(jwt, "sid"));
                if (scope == null) scope = scopeText(jwt.getClaim("scope"));
            }
        }
        String requestId = requestId(routingContext);
        return new SecurityEventRepository.Context(sessionId, scope, requestId);
    }

    private static String textClaim(JsonWebToken jwt, String name) {
        Object value = jwt.getClaim(name);
        return value == null ? null : value.toString();
    }

    private static String scopeText(Object value) {
        if (value instanceof Iterable<?> values) {
            java.util.List<String> entries = new java.util.ArrayList<>();
            for (Object item : values) if (item != null && !item.toString().isBlank()) entries.add(item.toString().trim());
            return entries.isEmpty() ? null : String.join(" ", entries);
        }
        if (value == null || value.toString().isBlank()) return null;
        return value.toString().trim();
    }

    private static String canonicalUuid(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return UuidValues.requireCanonical(value);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static String requestId(RoutingContext context) {
        if (context == null || context.request() == null) return null;
        String value = context.request().getHeader("X-Request-ID");
        if (value == null) return null;
        String normalized = value.trim();
        return normalized.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}") ? normalized : null;
    }
}
