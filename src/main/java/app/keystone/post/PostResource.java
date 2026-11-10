package app.keystone.post;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.NoSuchElementException;

@Path("/v1/posts")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class PostResource {
    @Inject PostRepository posts;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET public ApiResponse<List<Post>> list() { return ApiResponse.ok(posts.list()); }
    @POST @RolesAllowed("ADMIN") public Response create(PostRequest request) { if (request == null) return bad("request body is required"); try { var post = posts.create(request.code(), request.name(), request.sortOrder()); logs.record(actor(), "CREATE", "post", String.valueOf(post.id()), post.code()); return Response.status(201).entity(ApiResponse.ok(post)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RolesAllowed("ADMIN") public Response update(@PathParam("id") long id, PostRequest request) { if (request == null) return bad("request body is required"); try { var post = posts.update(id, request.name(), request.sortOrder(), request.enabled()); logs.record(actor(), "UPDATE", "post", String.valueOf(id), post.code()); return Response.ok(ApiResponse.ok(post)).build(); } catch (NoSuchElementException e) { return notFound(); } }
    @DELETE @Path("/{id}") @RolesAllowed("ADMIN") public Response delete(@PathParam("id") long id) { try { posts.delete(id); logs.record(actor(), "DELETE", "post", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (NoSuchElementException e) { return notFound(); } }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(400).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(404).entity(ApiResponse.error("post not found")).build(); }
    public record PostRequest(String code, String name, Integer sortOrder, Boolean enabled) {}
}
