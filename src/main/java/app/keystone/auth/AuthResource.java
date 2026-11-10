package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.user.UserRepository;
import io.smallrye.jwt.build.Jwt;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.time.Duration;

@Path("/v1/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {
    @Inject UserRepository users;
    @Inject SessionRepository sessions;
    @ConfigProperty(name = "mp.jwt.verify.issuer") String issuer;

    @POST @Path("/login") @PermitAll
    public Response login(LoginRequest request) {
        if (request == null || request.username() == null || request.password() == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("username and password are required")).build();
        }
        var user = users.authenticate(request.username(), request.password());
        if (user.isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid credentials")).build();
        var u = user.get();
        return Response.ok(ApiResponse.ok(issue(u, sessions.create(u.id())))).build();
    }

    @POST @Path("/refresh") @PermitAll
    public Response refresh(RefreshRequest request) {
        if (request == null || request.refreshToken() == null || request.refreshToken().isBlank()) return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("refreshToken is required")).build();
        var rotated = sessions.rotate(request.refreshToken(), users);
        if (rotated.isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid or expired refresh token")).build();
        var session = rotated.get();
        return Response.ok(ApiResponse.ok(issue(session.user(), session.refreshToken()))).build();
    }

    @POST @Path("/logout") @PermitAll
    public Response logout(RefreshRequest request, @HeaderParam("Authorization") String authorization) {
        if (request != null) sessions.revoke(request.refreshToken());
        return Response.ok(ApiResponse.ok(java.util.Map.of("loggedOut", true))).build();
    }

    private TokenResponse issue(UserRepository.AuthUser user, String refreshToken) {
        String accessToken = Jwt.issuer(issuer).upn(user.username()).groups(new java.util.HashSet<>(user.roles())).claim("userId", user.id()).expiresIn(Duration.ofHours(2)).sign();
        return new TokenResponse(accessToken, refreshToken, "Bearer", 7200, user.username(), user.displayName(), user.roles());
    }

    public record LoginRequest(String username, String password) {}
    public record RefreshRequest(String refreshToken) {}
    public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn, String username, String displayName, java.util.List<String> roles) {}
}
