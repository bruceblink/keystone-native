package app.keystone.auth;

import app.keystone.ApiResponse;
import app.keystone.HealthResource;
import app.keystone.audit.LoginLogRepository;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Compatibility endpoints matching the original Keystone login contract. */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class LegacyAuthResource {
    @Inject UserRepository users;
    @Inject SessionRepository sessions;
    @Inject LoginLogRepository loginLogs;
    @Inject MenuRepository menus;
    @Inject SecurityIdentity identity;
    @Inject AccessTokenService tokens;

    @POST @Path("login") @PermitAll
    public Response login(AuthResource.LoginRequest request, @HeaderParam("X-Forwarded-For") String ipAddress, @HeaderParam("User-Agent") String userAgent) {
        if (request == null || request.username() == null || request.password() == null) return Response.status(400).entity(ApiResponse.error("username and password are required")).build();
        var user = users.authenticate(request.username(), request.password());
        if (user.isEmpty()) { loginLogs.record(request.username(), "FAILURE", ipAddress, "invalid credentials", userAgent); return Response.status(401).entity(ApiResponse.error("invalid credentials")).build(); }
        if (user.get().mustChangePassword()) { loginLogs.record(user.get().username(), "BLOCKED", ipAddress, "password change required", userAgent); return Response.status(428).entity(ApiResponse.error("password change required")).build(); }
        var refresh = sessions.create(user.get().id(), Boolean.TRUE.equals(request.forceLogin()));
        if (refresh.isEmpty()) { loginLogs.record(user.get().username(), "BLOCKED", ipAddress, "account already has an active session", userAgent); return Response.status(Response.Status.CONFLICT).entity(ApiResponse.error("account already has an active session")).build(); }
        users.markLogin(user.get().id(), ipAddress);
        loginLogs.record(user.get().username(), "SUCCESS", ipAddress, "login successful", userAgent);
        return Response.ok(ApiResponse.ok(tokens.issue(user.get(), refresh.get().refreshToken(), refresh.get().accessTokenId(), refresh.get().sessionId(), refresh.get().refreshExpiresAt()))).build();
    }

    @POST @Path("refresh-token") @PermitAll
    public Response refresh(AuthResource.RefreshRequest request) {
        if (request == null) return Response.status(400).entity(ApiResponse.error("refreshToken is required")).build();
        var rotated = sessions.rotate(request.refreshToken(), users);
        if (rotated.isEmpty()) return Response.status(401).entity(ApiResponse.error("invalid or expired refresh token")).build();
        var session = rotated.get();
        return Response.ok(ApiResponse.ok(tokens.issue(session.user(), session.refreshToken(), session.accessTokenId(), session.sessionId(), session.refreshExpiresAt()))).build();
    }

    @POST @Path("logout-refresh-token") @PermitAll
    public Response logout(AuthResource.RefreshRequest request) { if (request != null) sessions.revoke(request.refreshToken()); return Response.ok(ApiResponse.ok(Map.of("loggedOut", true))).build(); }

    @POST @Path("change-initial-password") @PermitAll
    public Response changeInitialPassword(AuthResource.InitialPasswordRequest request) {
        if (request == null || request.username() == null || request.currentPassword() == null || request.newPassword() == null || request.newPassword().isBlank()) return Response.status(400).entity(ApiResponse.error("username, currentPassword and newPassword are required")).build();
        var user = users.authenticate(request.username(), request.currentPassword());
        if (user.isEmpty()) return Response.status(401).entity(ApiResponse.error("invalid credentials")).build();
        if (!user.get().mustChangePassword()) return Response.status(409).entity(ApiResponse.error("password change is not required")).build();
        users.update(user.get().id(), request.newPassword(), null, null, null, null);
        return Response.ok(ApiResponse.ok(Map.of("updated", true))).build();
    }

    @GET @Path("getLoginUserInfo") @RolesAllowed({"USER", "ADMIN"})
    public ApiResponse<UserRepository.AuthUser> loginUserInfo() { return ApiResponse.ok(users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(NotFoundException::new)); }

    @GET @Path("getRouters") @RolesAllowed({"USER", "ADMIN"})
    public ApiResponse<List<Router>> routers() { return ApiResponse.ok(toRouters(menus.listForRoles(identity.getRoles().stream().toList()))); }

    @GET @Path("getConfig") @PermitAll
    public ApiResponse<Map<String, Object>> config() { return ApiResponse.ok(Map.of("captchaEnabled", false, "isCaptchaOn", false, "registerEnabled", false)); }

    @GET @Path("captchaImage") @PermitAll
    public ApiResponse<Map<String, Object>> captchaImage() { return ApiResponse.ok(Map.of("captchaEnabled", false, "isCaptchaOn", false, "captchaCodeKey", "", "captchaCodeImg", "")); }

    @GET @Path("health") @PermitAll
    public ApiResponse<HealthResource.Health> health() { return ApiResponse.ok(new HealthResource.Health("UP", "keystone-native")); }

    @GET @Path("") @PermitAll
    public ApiResponse<HealthResource.Health> index() { return health(); }

    @GET @Path("login/rsa-public-key") @PermitAll
    public Response rsaPublicKey() {
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("keys/publicKey.pem")) {
            if (in == null) return Response.status(404).entity(ApiResponse.error("public key not found")).build();
            return Response.ok(ApiResponse.ok(Map.of("publicKey", new String(in.readAllBytes(), StandardCharsets.UTF_8)))).build();
        } catch (Exception e) { return Response.serverError().entity(ApiResponse.error("could not load public key")).build(); }
    }

    @POST @Path("register") @PermitAll
    public Response register() { return Response.status(Response.Status.NOT_IMPLEMENTED).entity(ApiResponse.error("registration is not supported")).build(); }

    private static List<Router> toRouters(List<app.keystone.menu.Menu> menus) {
        Map<Long, RouterBuilder> nodes = new LinkedHashMap<>();
        for (var menu : menus) {
            if ("BUTTON".equalsIgnoreCase(menu.menuType())) continue;
            Map<String, Object> meta = new LinkedHashMap<>(); meta.put("title", menu.name());
            if (menu.permission() != null && !menu.permission().isBlank()) meta.put("permission", menu.permission());
            nodes.put(menu.id(), new RouterBuilder(menu, new Router(menu.code(), menu.path() == null ? "/" + menu.code() : menu.path(), menu.component(), meta, List.of())));
        }
        List<RouterBuilder> roots = new ArrayList<>();
        for (var node : nodes.values()) {
            if (node.menu.parentId() == null || !nodes.containsKey(node.menu.parentId())) roots.add(node);
            else nodes.get(node.menu.parentId()).children.add(node);
        }
        return roots.stream().map(RouterBuilder::build).toList();
    }

    public record Router(String name, String path, String component, Map<String, Object> meta, List<Router> children) {}
    private static final class RouterBuilder {
        private final app.keystone.menu.Menu menu; private final Router router; private final List<RouterBuilder> children = new ArrayList<>();
        private RouterBuilder(app.keystone.menu.Menu menu, Router router) { this.menu = menu; this.router = router; }
        private Router build() { return new Router(router.name(), router.path(), router.component(), router.meta(), children.stream().map(RouterBuilder::build).toList()); }
    }
}
