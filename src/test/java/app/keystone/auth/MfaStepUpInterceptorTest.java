package app.keystone.auth;

import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InterceptorBinding;
import org.junit.jupiter.api.Test;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaStepUpInterceptorTest {
    @Test
    void bindingAndInterceptorAreRegistered() {
        assertTrue(RequiresMfaStepUp.class.isAnnotationPresent(InterceptorBinding.class));
        assertTrue(MfaStepUpInterceptor.class.isAnnotationPresent(Interceptor.class));
        assertNotNull(MfaStepUpInterceptor.class.getAnnotation(RequiresMfaStepUp.class));
    }

    @Test
    void apiKeyMutationsRequireStepUp() throws Exception {
        assertStepUp("issue", ApiKeyResource.Request.class);
        assertStepUp("rotate", String.class);
        assertStepUp("revoke", String.class);
    }

    @Test
    void mfaManagementRoutesRequireStepUpBoundary() throws Exception {
        assertStepUp(AuthResource.class, "beginMfaEnrollment");
        assertStepUp(AuthResource.class, "verifyMfaEnrollment", AuthResource.MfaCodeRequest.class);
        assertStepUp(AuthResource.class, "setMfaPolicy", long.class, AuthResource.MfaPolicyRequest.class);
    }

    @Test
    void claimsRecordKeepsRequiredSessionFields() {
        var claims = new MfaStepUpInterceptor.Claims(7L, "session-1", "web");
        assertEquals(7L, claims.userId());
        assertEquals("session-1", claims.sessionId());
        assertEquals("web", claims.clientId());
    }

    @Test
    void rejectsIncompleteOrInvalidJwtSessionClaims() {
        assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                () -> MfaStepUpInterceptor.claims(jwt(Map.of("userId", 7L, "client_id", "web"))));
        assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                () -> MfaStepUpInterceptor.claims(jwt(Map.of("userId", 0L, "sid", "session-1", "client_id", "web"))));
        assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                () -> MfaStepUpInterceptor.claims(jwt(Map.of("userId", 7L, "sid", "session-1", "client_id", "web;drop"))));
        var claims = MfaStepUpInterceptor.claims(jwt(Map.of("userId", "7", "sid", "session-1", "client_id", "web")));
        assertEquals(7L, claims.userId());
    }

    private static void assertStepUp(String name, Class<?> parameter) throws Exception {
        assertStepUp(ApiKeyResource.class, name, parameter);
    }

    private static void assertStepUp(Class<?> type, String name, Class<?>... parameters) throws Exception {
        Method method = type.getDeclaredMethod(name, parameters);
        assertNotNull(method.getAnnotation(RequiresMfaStepUp.class));
    }

    private static JsonWebToken jwt(Map<String, Object> claims) {
        return (JsonWebToken) Proxy.newProxyInstance(JsonWebToken.class.getClassLoader(), new Class<?>[]{JsonWebToken.class},
                (proxy, method, arguments) -> {
                    if ("getClaim".equals(method.getName())) return claims.get(arguments[0]);
                    if ("getName".equals(method.getName())) return "7";
                    if ("getClaimNames".equals(method.getName())) return claims.keySet();
                    if (method.getReturnType() == boolean.class) return false;
                    if (method.getReturnType() == int.class) return 0;
                    if (method.getReturnType() == long.class) return 0L;
                    return null;
                });
    }
}
