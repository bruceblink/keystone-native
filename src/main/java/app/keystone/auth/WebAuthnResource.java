package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.audit.SecurityEventRepository;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.webauthn.WebAuthnCredentialRecord;
import io.quarkus.security.webauthn.WebAuthnSecurity;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;

/** 将 WebAuthn 验证结果接入现有会话令牌体系，并限制凭据登记主体。 */
@Path("/v1/auth/webauthn")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class WebAuthnResource {
    @Inject WebAuthnSecurity webAuthn;
    @Inject NativeWebAuthnUserProvider credentials;
    @Inject WebAuthnConfiguration configuration;
    @Inject ApiKeyUserRepository users;
    @Inject SessionRepository sessions;
    @Inject AccessTokenService tokens;
    @Inject SecurityEventRepository securityEvents;
    @Inject SecurityIdentity identity;
    @Context RoutingContext routingContext;

    /** 已登录的人类用户才能取得注册挑战；challenge cookie 由 Quarkus 绑定到当前浏览器。 */
    @GET
    @Path("/register/options")
    @RejectApiKey
    public Response registerOptions() {
        var user = currentUser();
        if (user == null) return error(Response.Status.UNAUTHORIZED, "authentication_required", "authentication is required");
        try {
            ensureEnabled();
            var options = webAuthn.getRegisterChallenge(user.username(), user.displayName(), routingContext)
                    .await().indefinitely();
            return json(webAuthn.toJsonString(options));
        } catch (RuntimeException e) {
            return error(Response.Status.SERVICE_UNAVAILABLE, "authorization_unavailable", "WebAuthn is unavailable");
        }
    }

    /** 注册结果只允许绑定到当前会话用户，避免把凭据写入其他用户。 */
    @POST
    @Path("/register")
    @RejectApiKey
    public Response register(JsonObject body) {
        var user = currentUser();
        if (user == null) return error(Response.Status.UNAUTHORIZED, "authentication_required", "authentication is required");
        if (body == null) return error(Response.Status.BAD_REQUEST, "validation_failed", "credential response is required");
        try {
            ensureEnabled();
            WebAuthnCredentialRecord record = webAuthn.register(user.username(), body, routingContext).await().indefinitely();
            if (!user.username().equals(record.getUsername())) throw new IllegalArgumentException("credential user mismatch");
            credentials.store(record).await().indefinitely();
            securityEvents.record("WEBAUTHN_REGISTER", user.username(), "WEBAUTHN", record.getCredentialID(), null,
                    "auth", "register", "ALLOW", "WebAuthn credential registered");
            return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(java.util.Map.of("registered", true))).build();
        } catch (IllegalArgumentException e) {
            securityEvents.record("WEBAUTHN_REGISTER", user.username(), "WEBAUTHN", null, null,
                    "auth", "register", "DENY", "WebAuthn registration rejected");
            return error(Response.Status.BAD_REQUEST, "validation_failed", "invalid WebAuthn registration");
        } catch (RuntimeException e) {
            securityEvents.record("WEBAUTHN_REGISTER", user.username(), "WEBAUTHN", null, null,
                    "auth", "register", "DENY", "WebAuthn registration unavailable");
            return error(Response.Status.SERVICE_UNAVAILABLE, "authorization_unavailable", "WebAuthn is unavailable");
        }
    }

    /** 公开登录挑战；用户名可省略以支持 discoverable credentials。 */
    @GET
    @Path("/login/options")
    @PermitAll
    @RejectApiKey
    public Response loginOptions(@jakarta.ws.rs.QueryParam("username") String username) {
        try {
            ensureEnabled();
            String normalized = username == null || username.isBlank() ? null : username.trim();
            var options = webAuthn.getLoginChallenge(normalized, routingContext).await().indefinitely();
            return json(webAuthn.toJsonString(options));
        } catch (RuntimeException e) {
            return error(Response.Status.UNAUTHORIZED, "invalid_credential", "WebAuthn login is unavailable");
        }
    }

    /** 校验签名和计数器后创建现有刷新会话及短时访问令牌。 */
    @POST
    @Path("/login")
    @PermitAll
    @RejectApiKey
    public Response login(JsonObject body) {
        if (body == null) return error(Response.Status.BAD_REQUEST, "validation_failed", "credential response is required");
        try {
            ensureEnabled();
            WebAuthnCredentialRecord record = webAuthn.login(body, routingContext).await().indefinitely();
            var user = users.findAuthUserByUsername(record.getUsername()).orElseThrow(() -> new IllegalArgumentException("user not found"));
            String clientId = body.getString("clientId", SessionRepository.DEFAULT_CLIENT_ID);
            boolean forceLogin = body.getBoolean("forceLogin", false);
            credentials.update(record.getCredentialID(), record.getCounter()).await().indefinitely();
            var refresh = sessions.create(user.id(), forceLogin, clientId).orElseThrow(() -> new IllegalStateException("account already has an active session"));
            AuthResource.TokenResponse response;
            try {
                response = tokens.issue(user, refresh.refreshToken(), refresh.accessTokenId(), refresh.sessionId(),
                        refresh.clientId(), refresh.approvedScope(), refresh.refreshExpiresAt(), "AAL2", "webauthn");
            } catch (RuntimeException e) {
                sessions.revokeSession(refresh.sessionId());
                throw e;
            }
            securityEvents.record("WEBAUTHN_LOGIN", user.username(), "WEBAUTHN", record.getCredentialID(), null,
                    "auth", "login", "ALLOW", "WebAuthn login successful");
            return Response.ok(ApiResponse.ok(response)).build();
        } catch (IllegalArgumentException e) {
            securityEvents.record("WEBAUTHN_LOGIN", null, "WEBAUTHN", null, null,
                    "auth", "login", "DENY", "WebAuthn credential rejected");
            return error(Response.Status.UNAUTHORIZED, "invalid_credential", "WebAuthn authentication failed");
        } catch (RuntimeException e) {
            securityEvents.record("WEBAUTHN_LOGIN", null, "WEBAUTHN", null, null,
                    "auth", "login", "DENY", "WebAuthn authentication unavailable");
            return error(Response.Status.SERVICE_UNAVAILABLE, "authorization_unavailable", "WebAuthn is unavailable");
        }
    }

    private UserRepository.AuthUser currentUser() {
        if (identity == null || identity.isAnonymous() || !(identity.getPrincipal() instanceof JsonWebToken jwt)) return null;
        Object userId = JwtClaims.get(jwt, "userId");
        if (!(userId instanceof String id) || id.isBlank()) return null;
        return users.findAuthUser(id).orElse(null);
    }

    private void ensureEnabled() {
        if (!configuration.enabled()) throw new IllegalStateException("WebAuthn is disabled");
        configuration.validate();
    }

    private static Response json(String json) {
        return Response.ok(json).type(MediaType.APPLICATION_JSON).build();
    }

    private static Response error(Response.Status status, String code, String message) {
        return Response.status(status).entity(ApiResponse.error(code, message)).build();
    }
}
