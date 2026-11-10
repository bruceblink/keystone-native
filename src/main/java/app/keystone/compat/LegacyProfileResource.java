package app.keystone.compat;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.profile.ProfileResource;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/system/user/profile")
@Produces(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class LegacyProfileResource {
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET public ApiResponse<UserRepository.AuthUser> get() { return ApiResponse.ok(current()); }
    @PUT @Consumes(MediaType.APPLICATION_JSON) public Response update(ProfileResource.ProfileRequest request) { if (request == null || request.displayName() == null || request.displayName().isBlank()) return bad("displayName is required"); var user = current(); users.updateExtended(user.id(), null, request.displayName(), false, null, null, request.email(), request.phoneNumber(), request.sex(), request.avatar(), null, null, null); logs.record(user.username(), "UPDATE", "profile", String.valueOf(user.id()), null); return Response.ok(ApiResponse.ok(users.findAuthUser(user.id()).orElseThrow())).build(); }
    @PUT @Path("/password") @Consumes(MediaType.APPLICATION_JSON) public Response password(ProfileResource.PasswordRequest request) { if (request == null || request.password() == null || request.password().isBlank()) return bad("password is required"); var user = current(); users.update(user.id(), request.password(), null, null, null, null); logs.record(user.username(), "UPDATE", "profile-password", String.valueOf(user.id()), null); return Response.ok(ApiResponse.ok(java.util.Map.of("updated", true))).build(); }
    @POST @Path("/avatar") @Consumes(MediaType.APPLICATION_JSON) public Response avatar(ProfileResource.AvatarRequest request) { if (request == null || request.avatar() == null || request.avatar().isBlank()) return bad("avatar is required"); var user = current(); users.updateExtended(user.id(), null, null, false, null, null, null, null, null, request.avatar(), null, null, null); return Response.ok(ApiResponse.ok(java.util.Map.of("avatar", request.avatar()))).build(); }

    private UserRepository.AuthUser current() { return users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(NotFoundException::new); }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
}
