package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.audit.LoginLogRepository;
import app.keystone.user.UserRepository;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import io.quarkus.security.identity.SecurityIdentity;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/v1/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {
    @Inject UserRepository users;
    @Inject SessionRepository sessions;
    @Inject LoginLogRepository loginLogs;
    @Inject AccessTokenService tokens;
    @Inject SecurityIdentity identity;

    @POST @Path("/login") @PermitAll
    public Response login(LoginRequest request, @HeaderParam("X-Forwarded-For") String ipAddress, @HeaderParam("User-Agent") String userAgent) {
        if (request == null || request.username() == null || request.password() == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("username and password are required")).build();
        }
        var user = users.authenticate(request.username(), request.password());
        if (user.isEmpty()) { loginLogs.record(request.username(), "FAILURE", ipAddress, "invalid credentials", userAgent); return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid credentials")).build(); }
        var u = user.get();
        if (u.mustChangePassword()) { loginLogs.record(u.username(), "BLOCKED", ipAddress, "password change required", userAgent); return Response.status(428).entity(ApiResponse.error("password change required")).build(); }
        var refresh = sessions.create(u.id(), Boolean.TRUE.equals(request.forceLogin()));
        if (refresh.isEmpty()) { loginLogs.record(u.username(), "BLOCKED", ipAddress, "account already has an active session", userAgent); return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error("account already has an active session")).build(); }
        users.markLogin(u.id(), ipAddress);
        loginLogs.record(u.username(), "SUCCESS", ipAddress, "login successful", userAgent);
        return Response.ok(ApiResponse.ok(tokens.issue(u, refresh.get().refreshToken(), refresh.get().accessTokenId(), refresh.get().sessionId(), refresh.get().refreshExpiresAt()))).build();
    }

    @POST @Path("/refresh") @PermitAll
    public Response refresh(RefreshRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("refreshToken is required")).build();
        var rotated = sessions.rotate(request.refreshToken(), users);
        if (rotated.isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid or expired refresh token")).build();
        var session = rotated.get();
        return Response.ok(ApiResponse.ok(tokens.issue(session.user(), session.refreshToken(), session.accessTokenId(), session.sessionId(), session.refreshExpiresAt()))).build();
    }

    @POST @Path("/logout") @jakarta.annotation.security.RolesAllowed({"USER", "ADMIN"})
    public Response logout() {
        if (identity.isAnonymous() || !(identity.getPrincipal() instanceof JsonWebToken jwt)) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("authentication is required")).build();
        sessions.revokeSession(jwt.getClaim("sid"));
        return Response.ok(ApiResponse.ok(java.util.Map.of("loggedOut", true))).build();
    }

    @POST @Path("/change-initial-password") @PermitAll
    public Response changeInitialPassword(InitialPasswordRequest request) {
        if (request == null || request.username() == null || request.currentPassword() == null || request.newPassword() == null || request.newPassword().isBlank()) return Response.status(400).entity(ApiResponse.error("username, currentPassword and newPassword are required")).build();
        var user = users.authenticate(request.username(), request.currentPassword());
        if (user.isEmpty()) return Response.status(401).entity(ApiResponse.error("invalid credentials")).build();
        if (!user.get().mustChangePassword()) return Response.status(409).entity(ApiResponse.error("password change is not required")).build();
        users.update(user.get().id(), request.newPassword(), null, null, null, null);
        sessions.revokeAll(user.get().id());
        return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build();
    }

    public record LoginRequest(String username, String password, Boolean forceLogin) {}
    public record RefreshRequest(String refreshToken) {}
    public record InitialPasswordRequest(String username, String currentPassword, String newPassword) {}
    public record TokenResponse(String accessToken, String token, String refreshToken, String tokenType, long expiresIn, long refreshExpiresIn, String username, String displayName, java.util.List<String> roles) {}
}
