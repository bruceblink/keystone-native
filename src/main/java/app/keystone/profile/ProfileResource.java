package app.keystone.profile;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.user.UserRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.RejectApiKey;
import app.keystone.auth.SessionRepository;
import app.keystone.auth.RequiresMfaStepUp;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/v1/profile")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RejectApiKey
public class ProfileResource {
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject SessionRepository sessions;

    @GET @RequiresPermission("profile:read") public ApiResponse<UserRepository.AuthUser> get() { return ApiResponse.ok(current()); }
    @PUT @RequiresPermission("profile:write") public Response update(ProfileRequest request) {
        if (request == null || request.displayName() == null || request.displayName().isBlank()) return Response.status(400).entity(ApiResponse.error("displayName is required")).build();
        try { var user = current(); users.updateExtended(user.id(), null, request.displayName(), false, null, null, request.email(), request.phoneNumber(), request.sex(), request.avatar(), null, null, null); logs.record(user.username(), "UPDATE", "profile", String.valueOf(user.id()), null); return Response.ok(ApiResponse.ok(users.findAuthUser(user.id()).orElseThrow())).build(); }
        catch (java.util.NoSuchElementException e) { return Response.status(404).entity(ApiResponse.error("user not found")).build(); }
    }

    @PUT @Path("/avatar") @RequiresPermission("profile:write")
    public Response avatar(AvatarRequest request) {
        if (request == null || request.avatar() == null || request.avatar().isBlank()) return Response.status(400).entity(ApiResponse.error("avatar is required")).build();
        var user = current(); users.updateExtended(user.id(), null, null, false, null, null, null, null, null, request.avatar(), null, null, null); logs.record(user.username(), "UPDATE", "profile-avatar", String.valueOf(user.id()), null);
        return Response.ok(ApiResponse.ok(java.util.Map.of("avatar", request.avatar()))).build();
    }

    @PUT @Path("/password") @RequiresPermission("profile:write") @RequiresMfaStepUp
    public Response password(PasswordRequest request) {
        if (request == null || request.password() == null || request.password().isBlank()) return Response.status(400).entity(ApiResponse.error("password is required")).build();
        var user = current();
        users.update(user.id(), request.password(), null, null, null, null);
        sessions.revokeAll(user.id());
        logs.record(user.username(), "UPDATE", "profile-password", String.valueOf(user.id()), null);
        return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build();
    }

    private UserRepository.AuthUser current() { return users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(NotFoundException::new); }
    public record ProfileRequest(String displayName, String email, String phoneNumber, Integer sex, String avatar) {}
    public record PasswordRequest(String password) {}
    public record AvatarRequest(String avatar) {}
}
