package app.keystone.notice;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.NoSuchElementException;

@Path("/v1/notices")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class NoticeResource {
    @Inject NoticeRepository notices;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET @PermitAll public ApiResponse<List<Notice>> publicList() { return ApiResponse.ok(notices.list(true)); }
    @GET @Path("/manage") @RequiresPermission("notice:read") @app.keystone.auth.RequiresDataScope("notice") public ApiResponse<List<Notice>> manageList() { return ApiResponse.ok(notices.list(false)); }
    @POST @RequiresPermission("notice:create") @app.keystone.auth.RequiresDataScope("notice") public Response create(NoticeRequest request) { if (request == null) return bad("request body is required"); try { var notice = notices.create(request.title(), request.content(), request.noticeType(), actor()); logs.record(actor(), "CREATE", "notice", String.valueOf(notice.id()), notice.title()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(notice)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("notice:update") @app.keystone.auth.RequiresDataScope("notice") public Response update(@PathParam("id") String id, NoticeRequest request) { if (request == null) return bad("request body is required"); try { var notice = notices.update(id, request.title(), request.content(), request.noticeType(), request.enabled()); logs.record(actor(), "UPDATE", "notice", id, notice.title()); return Response.ok(ApiResponse.ok(notice)).build(); } catch (NoSuchElementException | IllegalArgumentException e) { return notFound(); } }
    @POST @Path("/{id}/publish") @RequiresPermission("notice:update") @app.keystone.auth.RequiresDataScope("notice") public Response publish(@PathParam("id") String id, PublishRequest request) { if (request == null || request.published() == null) return bad("published is required"); try { var notice = notices.publish(id, request.published()); logs.record(actor(), "PUBLISH", "notice", id, String.valueOf(request.published())); return Response.ok(ApiResponse.ok(notice)).build(); } catch (NoSuchElementException | IllegalArgumentException e) { return notFound(); } }
    @DELETE @Path("/{id}") @RequiresPermission("notice:delete") @app.keystone.auth.RequiresDataScope("notice") public Response delete(@PathParam("id") String id) { try { notices.delete(id); logs.record(actor(), "DELETE", "notice", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (NoSuchElementException | IllegalArgumentException e) { return notFound(); } }

    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(400).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(404).entity(ApiResponse.error("notice not found")).build(); }
    public record NoticeRequest(String title, String content, String noticeType, Boolean enabled) {}
    public record PublishRequest(Boolean published) {}
}
