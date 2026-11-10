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
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Duration;

@Path("/v1/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {
    @Inject UserRepository users;

    @POST @Path("/login") @PermitAll
    public Response login(LoginRequest request) {
        if (request == null || request.username() == null || request.password() == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error("username and password are required")).build();
        }
        var user = users.authenticate(request.username(), request.password());
        if (user.isEmpty()) return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse.error("invalid credentials")).build();
        var u = user.get();
        String token = Jwt.issuer("keystone-native").upn(u.username()).groups("USER").claim("userId", u.id()).expiresIn(Duration.ofHours(2)).sign();
        return Response.ok(ApiResponse.ok(new TokenResponse(token, "Bearer", 7200, u.username(), u.displayName()))).build();
    }

    public record LoginRequest(String username, String password) {}
    public record TokenResponse(String accessToken, String tokenType, long expiresIn, String username, String displayName) {}
}
