package app.keystone.profile;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.user.UserRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/v1/profile")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class ProfileResource {
    @Inject UserRepository users;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET public ApiResponse<UserRepository.AuthUser> get() { return ApiResponse.ok(current()); }
    @PUT public Response update(ProfileRequest request) {
        if (request == null || request.displayName() == null || request.displayName().isBlank()) return Response.status(400).entity(ApiResponse.error("displayName is required")).build();
        try { var user = current(); users.update(user.id(), null, request.displayName(), null, null, null); logs.record(user.username(), "UPDATE", "profile", String.valueOf(user.id()), null); return Response.ok(ApiResponse.ok(users.findAuthUser(user.id()).orElseThrow())).build(); }
        catch (java.util.NoSuchElementException e) { return Response.status(404).entity(ApiResponse.error("user not found")).build(); }
    }

    private UserRepository.AuthUser current() { return users.findAuthUserByUsername(identity.getPrincipal().getName()).orElseThrow(NotFoundException::new); }
    public record ProfileRequest(String displayName) {}
}
