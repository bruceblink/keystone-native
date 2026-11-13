package app.keystone.auth;

import app.keystone.ApiResponse;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.Duration;

/**
 * 在敏感操作前检查当前人类会话的 MFA step-up 状态。
 *
 * <p>API Key 没有交互式 MFA 会话，直接拒绝。Bearer JWT 必须同时提供
 * userId、sid 和 client_id；MFA 策略和最近验证时间都从数据库读取，读取失败时关闭请求。</p>
 */
@RequiresMfaStepUp
@Interceptor
@Priority(Interceptor.Priority.APPLICATION + 95)
public class MfaStepUpInterceptor {
    private static final Duration STEP_UP_AGE = Duration.ofMinutes(10);
    private static final String REQUIRED_ASSURANCE = "AAL2";

    @Inject SecurityIdentity identity;
    @Inject MfaRepository mfa;
    @Inject MfaSessionRepository sessions;

    @AroundInvoke
    Object check(InvocationContext context) throws Exception {
        if (identity == null || identity.isAnonymous()) {
            throw new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "authentication is required"));
        }
        if ("API_KEY".equals(identity.getAttribute("credentialType"))) {
            throw new ForbiddenException(ApiResponse.response(Response.Status.FORBIDDEN.getStatusCode(), "permission_denied", "MFA step-up requires a human session"));
        }
        if (!(identity.getPrincipal() instanceof JsonWebToken jwt)) {
            throw new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "human bearer authentication is required"));
        }
        Claims claims = Claims.from(jwt);
        try {
            var status = mfa.findStatus(claims.userId())
                    .orElseThrow(() -> new NotAuthorizedException("authentication subject is unavailable"));
            if (!status.required()) return context.proceed();
            if (!"AAL2".equals(claims.assurance()) || claims.authenticationMethods().stream().noneMatch(method -> method.equals("otp") || method.equals("recovery"))
                    || !status.enabled() || !sessions.hasRecentStepUp(claims.sessionId(), claims.userId(), claims.clientId(), STEP_UP_AGE, REQUIRED_ASSURANCE)) {
                throw new ForbiddenException(ApiResponse.response(Response.Status.FORBIDDEN.getStatusCode(), "permission_denied", "recent MFA step-up is required"));
            }
        } catch (NotAuthorizedException | ForbiddenException e) {
            throw e;
        } catch (IllegalStateException e) {
            throw new ServiceUnavailableException(ApiResponse.response(Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), "authorization_unavailable", "MFA state is unavailable"), e);
        }
        return context.proceed();
    }

    /** 从已签名 JWT 读取会话绑定字段；缺少任一字段都按未认证处理。 */
    static Claims claims(JsonWebToken jwt) {
        return Claims.from(jwt);
    }

    record Claims(String userId, String sessionId, String clientId, String tokenType, String assurance, java.util.List<String> authenticationMethods) {
        static Claims from(JsonWebToken jwt) {
            if (jwt == null) throw new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "human bearer authentication is required"));
            String userId = claimUuid(jwt, "userId");
            String sessionId = claimText(jwt, "sid");
            String clientId = claimText(jwt, "client_id");
            String tokenType = claimText(jwt, "type");
            String assurance = claimText(jwt, "aal");
            java.util.List<String> authenticationMethods = JwtClaims.strings(jwt, "amr");
            if (userId == null || sessionId == null || sessionId.isBlank() || clientId == null || clientId.isBlank()
                    || !"access".equals(tokenType) || !("AAL1".equals(assurance) || "AAL2".equals(assurance)) || authenticationMethods.isEmpty()
                    || !sessionId.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
                    || !clientId.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
                throw new NotAuthorizedException(ApiResponse.response(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_credential", "authentication session is incomplete"));
            }
            return new Claims(userId, sessionId, clientId, tokenType, assurance, authenticationMethods);
        }

        private static String claimText(JsonWebToken jwt, String name) {
            Object value = JwtClaims.get(jwt, name);
            return value == null ? null : value.toString();
        }

        private static String claimUuid(JsonWebToken jwt, String name) {
            Object value = JwtClaims.get(jwt, name);
            if (!(value instanceof String text)) return null;
            try { return app.keystone.identity.UuidValues.requireCanonical(text); }
            catch (IllegalArgumentException e) { return null; }
        }
    }
}
