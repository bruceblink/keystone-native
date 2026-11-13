package app.keystone.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Base64;

/** Reads custom JWT claims across MicroProfile JWT implementations. */
final class JwtClaims {
    private static final ObjectMapper JSON = new ObjectMapper();

    private JwtClaims() {}

    static Object get(JsonWebToken jwt, String name) {
        Object value = jwt.getClaim(name);
        if (value instanceof Number || value instanceof String) return value;
        try {
            String raw = jwt.getRawToken();
            if (raw == null) return null;
            String[] parts = raw.split("\\.", -1);
            if (parts.length != 3) return null;
            var node = JSON.readTree(Base64.getUrlDecoder().decode(parts[1])).get(name);
            if (node == null || node.isNull()) return null;
            return node.isNumber() ? node.numberValue() : node.asText();
        } catch (Exception e) {
            return null;
        }
    }
}
