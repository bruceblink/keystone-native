package app.keystone.post;

import app.keystone.ErrorCode;

import app.keystone.ApiResponse;
import app.keystone.ExcelExporter;
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

    /** page/size 或筛选条件传入时返回 {items,page,size,total}；省略时保留旧数组响应。 */
    @GET @RequiresPermission("post:read")
    public ApiResponse<?> list(
            @QueryParam("page") Integer page,
            @QueryParam("size") Integer size,
            @QueryParam("keyword") String keyword,
            @QueryParam("status") String status) {
        if (page == null && size == null && !hasFilter(keyword, status)) {
            return ApiResponse.ok(posts.list(context()));
        }
        return ApiResponse.ok(posts.list(context(), page == null ? 1 : page, size == null ? 20 : size, keyword, status));
    }
    @GET @Path("/export") @Produces(ExcelExporter.CONTENT_TYPE) @RequiresPermission("post:export")
    public Response export() {
        return Response.ok(PostExcelExporter.export(posts.export(context())))
                .type(ExcelExporter.CONTENT_TYPE)
                .header("Content-Disposition", "attachment; filename=posts.xlsx")
                .build();
    }
    @POST @RequiresPermission("post:create") public Response create(PostRequest request) { if (request == null) return bad("request body is required"); try { var post = posts.create(context(), request.code(), request.name(), request.sortOrder(), request.enabled()); logs.record(actor(), "CREATE", "post", String.valueOf(post.id()), post.code()); return Response.status(201).entity(ApiResponse.ok(post)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("post:update") public Response update(@PathParam("id") String id, PostRequest request) { if (request == null) return bad("request body is required"); try { var post = posts.update(context(), id, request.name(), request.sortOrder(), request.enabled()); logs.record(actor(), "UPDATE", "post", id, post.code()); return Response.ok(ApiResponse.ok(post)).build(); } catch (NoSuchElementException e) { return notFound(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } }
    @DELETE @Path("/{id}") @RequiresPermission("post:delete") public Response delete(@PathParam("id") String id) { try { posts.delete(context(), id); logs.record(actor(), "DELETE", "post", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (NoSuchElementException e) { return notFound(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } }
    private AuthorizationContext context() { return authorization.context(identity); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(ErrorCode.VALIDATION_FAILED, message)).build(); }
    private static Response notFound() { return Response.status(404).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, "post not found")).build(); }
    private static boolean hasFilter(String... values) { return java.util.Arrays.stream(values).anyMatch(value -> value != null && !value.isBlank()); }
    public record PostRequest(String code, String name, Integer sortOrder, Boolean enabled) {}
}
