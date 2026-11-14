package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.audit.LoginLogRepository;
import app.keystone.audit.SecurityObservability;
import app.keystone.user.UserRepository;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import io.quarkus.security.identity.SecurityIdentity;
import org.eclipse.microprofile.jwt.JsonWebToken;
import io.vertx.ext.web.RoutingContext;

@Path("/v1/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {
    @Inject UserRepository users;
    @Inject SessionRepository sessions;
    @Inject LoginLogRepository loginLogs;
    @Inject AccessTokenService tokens;
    @Inject SecurityIdentity identity;
    @Inject LoginRateLimiter loginRateLimiter;
    @Inject SecurityObservability securityObservability;
    @Inject MfaService mfa;
    @Inject MfaSessionRepository mfaSessions;
    @Inject ClientAddressResolver clientAddresses;
    @Context RoutingContext routingContext;

    @POST @Path("/login") @PermitAll @RejectApiKey
    public Response login(LoginRequest request, @HeaderParam("X-Forwarded-For") String ipAddress, @HeaderParam("User-Agent") String userAgent) {
        if (request == null || request.username() == null || request.password() == null) {
            return Response.status(422).entity(ApiResponse.error("username and password are required")).build();
        }
        String clientAddress = clientAddresses.resolve(routingContext, ipAddress);
        try {
            if (loginRateLimiter.isBlocked(request.username(), clientAddress)) {
                securityObservability.loginFailure(true);
                return Response.status(429).entity(ApiResponse.error("too many login attempts")).build();
            }
        }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        var user = users.authenticate(request.username(), request.password());
        if (user.isEmpty()) {
            boolean blocked;
            try { blocked = loginRateLimiter.recordFailure(request.username(), clientAddress); }
            catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
            securityObservability.loginFailure(blocked);
            loginLogs.record(request.username(), "FAILURE", clientAddress, "invalid credentials", userAgent); return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid credentials")).build();
        }
        var u = user.get();
        try { loginRateLimiter.clear(u.username(), clientAddress); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        if (u.mustChangePassword()) { loginLogs.record(u.username(), "BLOCKED", clientAddress, "password change required", userAgent); return Response.status(428).entity(ApiResponse.error("password change required")).build(); }
        MfaService.LoginPreparation preparation;
        try { preparation = mfa.prepareLogin(u.id(), request.clientId()); }
        catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        if (preparation.required() && preparation.challenge() == null) {
            loginLogs.record(u.username(), "BLOCKED", clientAddress, "MFA enrollment required", userAgent);
            return Response.status(428).entity(ApiResponse.error("MFA enrollment required")).build();
        }
        if (preparation.challenge() != null) {
            loginLogs.record(u.username(), "MFA_REQUIRED", clientAddress, "MFA challenge issued", userAgent);
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ApiResponse<>(false, new MfaRequired(preparation.challenge().challengeId(), preparation.challenge().clientId(), preparation.challenge().expiresAt()), "MFA_REQUIRED", "invalid_credential"))
                    .build();
        }
        java.util.Optional<SessionRepository.CreatedSession> refresh;
        try { refresh = sessions.create(u.id(), Boolean.TRUE.equals(request.forceLogin()), request.clientId()); }
        catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        if (refresh.isEmpty()) { loginLogs.record(u.username(), "BLOCKED", clientAddress, "account already has an active session", userAgent); return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error("account already has an active session")).build(); }
        Response tokenResponse;
        try {
            tokenResponse = Response.ok(ApiResponse.ok(tokens.issue(u, refresh.get().refreshToken(), refresh.get().accessTokenId(), refresh.get().sessionId(), refresh.get().clientId(), refresh.get().approvedScope(), refresh.get().refreshExpiresAt()))).build();
        } catch (IllegalStateException e) { return tokenUnavailable(refresh.get().sessionId()); }
        users.markLogin(u.id(), clientAddress);
        loginLogs.record(u.username(), "SUCCESS", clientAddress, "login successful", userAgent);
        return tokenResponse;
    }

    @POST @Path("/refresh") @PermitAll @RejectApiKey
    public Response refresh(RefreshRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) return Response.status(422).entity(ApiResponse.error("refreshToken is required")).build();
        java.util.Optional<SessionRepository.RotatedSession> rotated;
        try { rotated = sessions.rotate(request.refreshToken(), users, request.clientId()); }
        catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        if (rotated.isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid or expired refresh token")).build();
        var session = rotated.get();
        try {
            return Response.ok(ApiResponse.ok(tokens.issue(session.user(), session.refreshToken(), session.accessTokenId(), session.sessionId(), session.clientId(), session.approvedScope(), session.refreshExpiresAt()))).build();
        } catch (IllegalStateException e) { return tokenUnavailable(session.sessionId()); }
    }

    /** 用登录验证请求完成第二因素后才创建刷新会话。 */
    @POST @Path("/mfa/verify") @PermitAll @RejectApiKey
    public Response verifyMfa(LoginMfaRequest request, @HeaderParam("X-Forwarded-For") String ipAddress, @HeaderParam("User-Agent") String userAgent) {
        if (request == null || request.username() == null || request.challengeId() == null || request.code() == null) {
            return Response.status(422).entity(ApiResponse.error("username, challengeId and code are required")).build();
        }
        String clientAddress = clientAddresses.resolve(routingContext, ipAddress);
        var user = users.findAuthUserByUsername(request.username().trim());
        if (user.isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid MFA challenge")).build();
        MfaService.LoginVerification verification;
        try {
            verification = mfa.verifyLogin(user.get().id(), request.challengeId(), request.clientId(), request.code(), clientAddress).orElse(null);
        } catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        if (verification == null) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid MFA challenge")).build();
        java.util.Optional<SessionRepository.CreatedSession> refresh;
        try { refresh = sessions.create(user.get().id(), Boolean.TRUE.equals(request.forceLogin()), request.clientId()); }
        catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        if (refresh.isEmpty()) return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error("account already has an active session")).build();
        var created = refresh.get();
        try {
            if (!mfaSessions.markVerified(created.sessionId(), user.get().id(), created.clientId(), verification.assurance(), verification.amr())) {
                sessions.revokeSession(created.sessionId());
                return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build();
            }
        } catch (IllegalStateException e) {
            sessions.revokeSession(created.sessionId());
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build();
        }
        Response tokenResponse;
        try {
            tokenResponse = Response.ok(ApiResponse.ok(tokens.issue(user.get(), created.refreshToken(), created.accessTokenId(), created.sessionId(), created.clientId(), created.approvedScope(), created.refreshExpiresAt(), verification.assurance(), verification.amr()))).build();
        } catch (IllegalStateException e) { return tokenUnavailable(created.sessionId()); }
        users.markLogin(user.get().id(), clientAddress);
        loginLogs.record(user.get().username(), "SUCCESS", clientAddress, "MFA login successful", userAgent);
        return tokenResponse;
    }

    /** 为当前已登录的人类用户创建待验证 TOTP enrollment。 */
    @POST @Path("/mfa/enroll") @RequiresPermission("mfa:manage") @RequiresMfaStepUp @RejectApiKey
    public Response beginMfaEnrollment() {
        var current = currentHumanSession();
        try {
            var result = mfa.beginEnrollment(current.userId(), identity.getPrincipal().getName(), current.clientId(), current.sessionId());
            return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(result)).build();
        } catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) {
            if ("MFA is already enabled".equals(e.getMessage())) return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error(e.getMessage())).build();
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("MFA state is unavailable")).build();
        }
    }

    /** 只接受当前会话绑定的 enrollment 验证请求，并在成功后返回一次性恢复码。 */
    @RequiresPermission("mfa:manage") @RequiresMfaStepUp @RejectApiKey
    public Response verifyMfaEnrollment(MfaCodeRequest request) {
        return verifyMfaEnrollment(request, null);
    }

    @POST @Path("/mfa/enroll/verify") @RequiresPermission("mfa:manage") @RequiresMfaStepUp @RejectApiKey
    public Response verifyMfaEnrollment(MfaCodeRequest request, @HeaderParam("X-Forwarded-For") String ipAddress) {
        if (request == null || request.challengeId() == null || request.code() == null) return Response.status(422).entity(ApiResponse.error("challengeId and code are required")).build();
        var current = currentHumanSession();
        String clientAddress = clientAddresses.resolve(routingContext, ipAddress);
        try {
            var result = mfa.verifyEnrollment(current.userId(), request.challengeId(), current.clientId(), current.sessionId(), request.code(), clientAddress);
            return result.<Response>map(value -> Response.ok(ApiResponse.ok(value)).build())
                    .orElseGet(() -> Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid MFA challenge")).build());
        } catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("MFA state is unavailable")).build(); }
    }

    /** 使用当前密码和最近的 MFA 验证轮换恢复码，旧批次在数据库事务内失效。 */
    @POST @Path("/mfa/recovery-codes/rotate") @RequiresPermission("mfa:manage") @RequiresMfaStepUp @RejectApiKey
    public Response rotateRecoveryCodes(CurrentPasswordRequest request) {
        if (request == null || request.currentPassword() == null || request.currentPassword().isBlank()) return Response.status(422).entity(ApiResponse.error("currentPassword is required")).build();
        var current = currentHumanSession();
        String username = identity.getPrincipal().getName();
        try {
            if (users.authenticate(username, request.currentPassword()).isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid credentials")).build();
        } catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("authentication state is unavailable")).build(); }
        try { return Response.ok(ApiResponse.ok(java.util.Map.of("recoveryCodes", mfa.rotateRecoveryCodes(current.userId())))).build(); }
        catch (IllegalStateException e) {
            if ("MFA is not enabled".equals(e.getMessage())) return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error(e.getMessage())).build();
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("MFA state is unavailable")).build();
        }
    }

    /** 管理员只可为已经完成 enrollment 的用户启用或关闭强制 MFA。 */
    @PUT @Path("/mfa/policy/{userId}") @RequiresPermission("mfa:manage") @RequiresMfaStepUp @RejectApiKey
    public Response setMfaPolicy(@PathParam("userId") String userId, MfaPolicyRequest request) {
        if (request == null || request.required() == null || userId == null) return Response.status(422).entity(ApiResponse.error("userId and required are required")).build();
        try {
            if (!mfa.setRequired(userId, request.required())) return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error("MFA enrollment is required before enabling policy")).build();
            sessions.revokeAll(userId);
            return Response.ok(ApiResponse.ok(java.util.Map.of("userId", userId, "required", request.required()))).build();
        } catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        catch (IllegalStateException e) { return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("MFA state is unavailable")).build(); }
    }

    @POST @Path("/logout") @RequiresPermission("session:revoke")
    public Response logout() {
        if (identity.isAnonymous() || !(identity.getPrincipal() instanceof JsonWebToken jwt)) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("authentication is required")).build();
        Object sessionId = JwtClaims.get(jwt, "sid");
        if (sessionId == null || sessionId.toString().isBlank()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("authentication session is incomplete")).build();
        sessions.revokeSession(sessionId.toString());
        return Response.ok(ApiResponse.ok(java.util.Map.of("loggedOut", true))).build();
    }

    @POST @Path("/change-initial-password") @PermitAll @RejectApiKey
    public Response changeInitialPassword(InitialPasswordRequest request) {
        if (request == null || request.username() == null || request.currentPassword() == null || request.newPassword() == null || request.newPassword().isBlank()) return Response.status(422).entity(ApiResponse.error("username, currentPassword and newPassword are required")).build();
        var user = users.authenticate(request.username(), request.currentPassword());
        if (user.isEmpty()) return Response.status(401).entity(ApiResponse.error("invalid credentials")).build();
        if (!user.get().mustChangePassword()) return Response.status(409).entity(ApiResponse.error("password change is not required")).build();
        try { users.updateInitialPassword(AuthorizationContext.system(), user.get().id(), request.newPassword()); }
        catch (IllegalArgumentException e) { return Response.status(422).entity(ApiResponse.error(e.getMessage())).build(); }
        sessions.revokeAll(user.get().id());
        return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build();
    }

    public record LoginRequest(String username, String password, Boolean forceLogin, String clientId) {}
    public record RefreshRequest(String refreshToken, String clientId) {}
    public record InitialPasswordRequest(String username, String currentPassword, String newPassword) {}
    public record MfaRequired(String challengeId, String clientId, java.time.Instant expiresAt) {}
    public record LoginMfaRequest(String username, String challengeId, String code, String clientId, Boolean forceLogin) {}
    public record MfaCodeRequest(String challengeId, String code) {}
    public record MfaPolicyRequest(Boolean required) {}
    public record CurrentPasswordRequest(String currentPassword) {}
    public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn, long refreshExpiresIn, String username, String displayName, java.util.List<String> roles, String sessionId, String clientId) {}

    private CurrentHumanSession currentHumanSession() {
        if (identity == null || identity.isAnonymous() || !(identity.getPrincipal() instanceof JsonWebToken jwt)) throw new jakarta.ws.rs.NotAuthorizedException("authentication is required");
        String sessionId = claimText(jwt, "sid");
        String clientId = claimText(jwt, "client_id");
        String userId = claimUuid(jwt, "userId");
        if (userId == null || sessionId == null || clientId == null) throw new jakarta.ws.rs.NotAuthorizedException("authentication session is incomplete");
        return new CurrentHumanSession(userId, sessionId, clientId);
    }

    private static String claimText(JsonWebToken jwt, String name) { Object value = JwtClaims.get(jwt, name); return value == null ? null : value.toString(); }
    private static String claimUuid(JsonWebToken jwt, String name) { Object value = JwtClaims.get(jwt, name); if (!(value instanceof String text)) return null; try { return app.keystone.identity.UuidValues.requireCanonical(text); } catch (IllegalArgumentException e) { return null; } }
    /** 签发失败时撤销刚创建或刚轮换的会话，避免令牌不可用但刷新状态仍保持活动。 */
    private Response tokenUnavailable(String sessionId) {
        try { sessions.revokeSession(sessionId); } catch (IllegalStateException ignored) { }
        return Response.status(Response.Status.SERVICE_UNAVAILABLE).entity(ApiResponse.error("token service is unavailable")).build();
    }
    private record CurrentHumanSession(String userId, String sessionId, String clientId) {}
}
