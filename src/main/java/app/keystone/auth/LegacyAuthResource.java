package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.HealthResource;
import app.keystone.menu.MenuRepository;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.jwt.build.Jwt;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;

/** Compatibility endpoints matching the original Keystone login contract. */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class LegacyAuthResource {
    @Inject UserRepository users;
    @Inject SessionRepository sessions;
    @Inject MenuRepository menus;
    @Inject SecurityIdentity identity;
    @ConfigProperty(name = "mp.jwt.verify.issuer") String issuer;

    @POST @Path("login") @PermitAll
    public Response login(AuthResource.LoginRequest request) {
        if (request == null || request.username() == null || request.password() == null) return Response.status(400).entity(ApiResponse.error("username and password are required")).build();
        var user = users.authenticate(request.username(), request.password());
        if (user.isEmpty()) return Response.status(401).entity(ApiResponse.error("invalid credentials")).build();
        if (user.get().mustChangePassword()) return Response.status(428).entity(ApiResponse.error("password change required")).build();
        return Response.ok(ApiResponse.ok(issue(user.get(), sessions.create(user.get().id())))).build();
    }

    @POST @Path("refresh-token") @PermitAll
    public Response refresh(AuthResource.RefreshRequest request) {
        if (request == null) return Response.status(400).entity(ApiResponse.error("refreshToken is required")).build();
        var rotated = sessions.rotate(request.refreshToken(), users);
        if (rotated.isEmpty()) return Response.status(401).entity(ApiResponse.error("invalid or expired refresh token")).build();
        var session = rotated.get();
        return Response.ok(ApiResponse.ok(issue(session.user(), session.refreshToken()))).build();
    }

    @POST @Path("logout-refresh-token") @PermitAll
    public Response logout(AuthResource.RefreshRequest request) { if (request != null) sessions.revoke(request.refreshToken()); return Response.ok(ApiResponse.ok(Map.of("loggedOut", true))).build(); }

    @GET @Path("getLoginUserInfo") @RolesAllowed({"USER", "ADMIN"})
    public ApiResponse<UserRepository.AuthUser> loginUserInfo() { return ApiResponse.ok(users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(NotFoundException::new)); }

    @GET @Path("getRouters") @RolesAllowed({"USER", "ADMIN"})
    public ApiResponse<java.util.List<app.keystone.menu.Menu>> routers() { return ApiResponse.ok(menus.listForRoles(identity.getRoles().stream().toList())); }

    @GET @Path("getConfig") @PermitAll
    public ApiResponse<Map<String, Object>> config() { return ApiResponse.ok(Map.of("captchaEnabled", false, "registerEnabled", false)); }

    @GET @Path("health") @PermitAll
    public ApiResponse<HealthResource.Health> health() { return ApiResponse.ok(new HealthResource.Health("UP", "keystone-native")); }

    @GET @Path("login/rsa-public-key") @PermitAll
    public Response rsaPublicKey() {
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("keys/publicKey.pem")) {
            if (in == null) return Response.status(404).entity(ApiResponse.error("public key not found")).build();
            return Response.ok(ApiResponse.ok(new String(in.readAllBytes(), StandardCharsets.UTF_8))).build();
        } catch (Exception e) { return Response.serverError().entity(ApiResponse.error("could not load public key")).build(); }
    }

    private AuthResource.TokenResponse issue(UserRepository.AuthUser user, String refreshToken) {
        String access = Jwt.issuer(issuer).upn(user.username()).groups(new HashSet<>(user.roles())).claim("userId", user.id()).expiresIn(Duration.ofHours(2)).sign();
        return new AuthResource.TokenResponse(access, refreshToken, "Bearer", 7200, user.username(), user.displayName(), user.roles());
    }
}
