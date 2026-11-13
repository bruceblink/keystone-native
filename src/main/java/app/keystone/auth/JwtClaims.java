package app.keystone.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Base64;
import java.util.ArrayList;
import java.util.List;

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

    /** 读取 JWT 数组声明，兼容 SmallRye 已解析集合和原始 JSON 数组。 */
    static List<String> strings(JsonWebToken jwt, String name) {
        List<String> result = new ArrayList<>();
        if (jwt == null) return result;
        Object direct = jwt.getClaim(name);
        if (direct instanceof Iterable<?> values) {
            for (Object value : values) if (value instanceof String text && !text.isBlank()) result.add(text);
            return List.copyOf(result);
        }
        if (direct instanceof String text && !text.isBlank()) return List.of(text);
        try {
            String raw = jwt.getRawToken();
            if (raw == null) return List.of();
            String[] parts = raw.split("\\.", -1);
            if (parts.length != 3) return List.of();
            var node = JSON.readTree(Base64.getUrlDecoder().decode(parts[1])).get(name);
            if (node == null || !node.isArray()) return List.of();
            node.forEach(item -> { if (item.isTextual() && !item.asText().isBlank()) result.add(item.asText()); });
        } catch (Exception ignored) {
            return List.of();
        }
        return List.copyOf(result);
    }
}
