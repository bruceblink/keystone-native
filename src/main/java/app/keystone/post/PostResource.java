package app.keystone.post;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.NoSuchElementException;

@Path("/v1/posts")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("post")
public class PostResource {
    @Inject PostRepository posts;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @RequiresPermission("post:read")
    public ApiResponse<List<Post>> list() { return ApiResponse.ok(posts.list(context())); }
    @POST @RequiresPermission("post:create") public Response create(PostRequest request) { if (request == null) return bad("request body is required"); try { var post = posts.create(context(), request.code(), request.name(), request.sortOrder()); logs.record(actor(), "CREATE", "post", String.valueOf(post.id()), post.code()); return Response.status(201).entity(ApiResponse.ok(post)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("post:update") public Response update(@PathParam("id") String id, PostRequest request) { if (request == null) return bad("request body is required"); try { var post = posts.update(context(), id, request.name(), request.sortOrder(), request.enabled()); logs.record(actor(), "UPDATE", "post", id, post.code()); return Response.ok(ApiResponse.ok(post)).build(); } catch (NoSuchElementException e) { return notFound(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } }
    @DELETE @Path("/{id}") @RequiresPermission("post:delete") public Response delete(@PathParam("id") String id) { try { posts.delete(context(), id); logs.record(actor(), "DELETE", "post", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (NoSuchElementException e) { return notFound(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } }
    private AuthorizationContext context() { return authorization.context(identity); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(400).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(404).entity(ApiResponse.error("post not found")).build(); }
    public record PostRequest(String code, String name, Integer sortOrder, Boolean enabled) {}
}
