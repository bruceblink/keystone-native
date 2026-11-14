package app.keystone.http;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 验证 API 响应的统一安全头和缓存边界。 */
class SecurityHeadersFilterTest {
    @Test
    void addsHeadersAndNoStoreForJsonApiResponse() {
        var filter = new SecurityHeadersFilter();
        filter.hstsEnabled = true;
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        var response = response(headers, jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE);
        filter.filter(request("/api/v1/users"), response);

        assertEquals("nosniff", headers.getFirst("X-Content-Type-Options"));
        assertEquals("DENY", headers.getFirst("X-Frame-Options"));
        assertEquals("no-referrer", headers.getFirst("Referrer-Policy"));
        assertEquals("max-age=31536000; includeSubDomains", headers.getFirst("Strict-Transport-Security"));
        assertEquals("no-store, max-age=0", headers.getFirst("Cache-Control"));
    }

    @Test
    void doesNotAddHstsWhenDisabled() {
        var filter = new SecurityHeadersFilter();
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        filter.filter(request("/api/v1/health"), response(headers, null));

        assertEquals(null, headers.getFirst("Strict-Transport-Security"));
        assertEquals("no-store, max-age=0", headers.getFirst("Cache-Control"));
    }

    private static ContainerRequestContext request(String path) {
        UriInfo uriInfo = (UriInfo) Proxy.newProxyInstance(UriInfo.class.getClassLoader(), new Class<?>[]{UriInfo.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getPath" -> path.substring(path.indexOf("/api/") + 5);
                    case "getRequestUri" -> URI.create("http://localhost" + path);
                    default -> null;
                });
        return (ContainerRequestContext) Proxy.newProxyInstance(ContainerRequestContext.class.getClassLoader(), new Class<?>[]{ContainerRequestContext.class},
                (proxy, method, args) -> "getUriInfo".equals(method.getName()) ? uriInfo : null);
    }

    private static ContainerResponseContext response(MultivaluedMap<String, Object> headers, jakarta.ws.rs.core.MediaType mediaType) {
        return (ContainerResponseContext) Proxy.newProxyInstance(ContainerResponseContext.class.getClassLoader(), new Class<?>[]{ContainerResponseContext.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getHeaders" -> headers;
                    case "getMediaType" -> mediaType;
                    default -> null;
                });
    }
}
