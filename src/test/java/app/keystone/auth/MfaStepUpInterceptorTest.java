package app.keystone.auth;

import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InterceptorBinding;
import org.junit.jupiter.api.Test;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.resteasy.reactive.multipart.FileUpload;
import app.keystone.user.UserResource;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaStepUpInterceptorTest {
    private static final String USER_ID = "00000000-0000-7000-8000-000000000007";
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
        assertStepUp(AuthResource.class, "setMfaPolicy", String.class, AuthResource.MfaPolicyRequest.class);
        assertStepUp(AuthResource.class, "rotateRecoveryCodes", AuthResource.CurrentPasswordRequest.class);
    }

    @Test
    void userImportAlwaysRequiresAal2() throws Exception {
        var method = UserResource.class.getDeclaredMethod("importUsers", FileUpload.class);
        var requirement = method.getAnnotation(RequiresMfaStepUp.class);
        assertNotNull(requirement);
        assertTrue(requirement.enforce());
    }

    @Test
    void webauthnRegistrationRequiresStepUpBoundary() throws Exception {
        assertStepUp(WebAuthnResource.class, "registerOptions");
        assertStepUp(WebAuthnResource.class, "register", io.vertx.core.json.JsonObject.class);
    }

    @Test
    void claimsRecordKeepsRequiredSessionFields() {
        var claims = new MfaStepUpInterceptor.Claims(USER_ID, "session-1", "web", "access", "AAL2", java.util.List.of("otp"));
        assertEquals(USER_ID, claims.userId());
        assertEquals("session-1", claims.sessionId());
        assertEquals("web", claims.clientId());
        assertEquals("access", claims.tokenType());
        assertEquals("AAL2", claims.assurance());
        assertTrue(claims.authenticationMethods().contains("otp"));
    }

    @Test
    void rejectsIncompleteOrInvalidJwtSessionClaims() {
        assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                () -> MfaStepUpInterceptor.claims(jwt(Map.of("userId", USER_ID, "client_id", "web", "type", "access", "aal", "AAL1", "amr", java.util.List.of("pwd")))));
        assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                () -> MfaStepUpInterceptor.claims(jwt(Map.of("userId", "not-a-uuid", "sid", "session-1", "client_id", "web", "type", "access", "aal", "AAL1", "amr", java.util.List.of("pwd")))));
        assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                () -> MfaStepUpInterceptor.claims(jwt(Map.of("userId", USER_ID, "sid", "session-1", "client_id", "web;drop", "type", "access", "aal", "AAL1", "amr", java.util.List.of("pwd")))));
        var claims = MfaStepUpInterceptor.claims(jwt(Map.of("userId", USER_ID, "sid", "session-1", "client_id", "web", "type", "access", "aal", "AAL2", "amr", java.util.List.of("otp"))));
        assertEquals(USER_ID, claims.userId());
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
