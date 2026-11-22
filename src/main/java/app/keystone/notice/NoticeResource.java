package app.keystone.notice;

import com.fasterxml.jackson.databind.JsonNode;
import app.keystone.ErrorCode;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
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
    @Inject AuthorizationService authorization;

    @GET @PermitAll public ApiResponse<List<Notice>> publicList() { return ApiResponse.ok(notices.list(null, true)); }
    /** page/size 传入时返回分页对象；省略时保留旧数组响应，兼容旧调用方。 */
    @GET @Path("/manage") @RequiresPermission("notice:read") @app.keystone.auth.RequiresDataScope("notice") public ApiResponse<?> manageList(
            @QueryParam("page") Integer page,
            @QueryParam("size") Integer size,
            @QueryParam("keyword") String keyword,
            @QueryParam("title") String title,
            @QueryParam("content") String content,
            @QueryParam("noticeType") String noticeType,
            @QueryParam("type") String type,
            @QueryParam("status") String status,
            @QueryParam("published") Boolean published) {
        if (page == null && size == null) return ApiResponse.ok(notices.list(context(), false));
        return ApiResponse.ok(notices.list(context(), page == null ? 1 : page, size == null ? 20 : size,
                keyword, title, content, noticeType == null ? type : noticeType, status, published));
    }
    @POST @RequiresPermission("notice:create") @app.keystone.auth.RequiresDataScope("notice") public Response create(NoticeRequest request) { if (request == null) return bad("request body is required"); var typeError = invalidNoticeType(request.noticeType()); if (typeError != null) return typeError; try { var notice = notices.create(context(), request.title(), request.content(), request.noticeType(), actor(), request.enabled()); logs.record(actor(), "CREATE", "notice", String.valueOf(notice.id()), notice.title()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(notice)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("notice:update") @app.keystone.auth.RequiresDataScope("notice") public Response update(@PathParam("id") String id, NoticeRequest request) { if (request == null) return bad("request body is required"); var typeError = invalidNoticeType(request.noticeType()); if (typeError != null) return typeError; try { var notice = notices.update(context(), id, request.title(), request.content(), request.noticeType(), request.enabled()); logs.record(actor(), "UPDATE", "notice", id, notice.title()); return Response.ok(ApiResponse.ok(notice)).build(); } catch (NoSuchElementException | IllegalArgumentException e) { return notFound(); } }
    @POST @Path("/{id}/publish") @RequiresPermission("notice:update") @app.keystone.auth.RequiresDataScope("notice") public Response publish(@PathParam("id") String id, PublishRequest request) { if (request == null || request.published() == null || !request.published().isBoolean()) return invalidPublished(); boolean published = request.published().booleanValue(); try { var notice = notices.publish(context(), id, published); logs.record(actor(), "PUBLISH", "notice", id, String.valueOf(published)); return Response.ok(ApiResponse.ok(notice)).build(); } catch (NoSuchElementException | IllegalArgumentException e) { return notFound(); } }
    @DELETE @Path("/{id}") @RequiresPermission("notice:delete") @app.keystone.auth.RequiresDataScope("notice") public Response delete(@PathParam("id") String id) { try { notices.delete(context(), id); logs.record(actor(), "DELETE", "notice", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (NoSuchElementException | IllegalArgumentException e) { return notFound(); } }
    @DELETE @RequiresPermission("notice:delete") @app.keystone.auth.RequiresDataScope("notice")
    public Response deleteBatch(@QueryParam("notice_ids") String noticeIds) {
        String rawIds = noticeIds;
        try {
            int deleted = notices.deleteAll(context(), splitIds(rawIds));
            logs.record(actor(), "DELETE", "notices", null, "batch deleted=" + deleted);
            return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", deleted))).build();
        } catch (IllegalArgumentException e) { return invalidNoticeIds(); }
        catch (NoSuchElementException e) { return notFound(); }
    }

    private AuthorizationContext context() { return authorization.context(identity); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(ErrorCode.VALIDATION_FAILED, message)).build(); }
    private static Response invalidPublished() { return Response.status(422).entity(ApiResponse.error(ErrorCode.NOTICE_PUBLISHED_INVALID, "published must be a boolean")).build(); }
    private static Response invalidNoticeIds() { return Response.status(422).entity(ApiResponse.error(ErrorCode.NOTICE_IDS_INVALID, "notice_ids must be comma separated UUIDs")).build(); }
    /** 在查询或持久化前按 Unicode 码点校验公告类型，避免更新入口把校验错误误报为 404。 */
    private static Response invalidNoticeType(String noticeType) {
        if (noticeType == null || noticeType.codePointCount(0, noticeType.length()) <= 32) return null;
        return Response.status(422).entity(ApiResponse.error(ErrorCode.NOTICE_TYPE_INVALID,
                "noticeType must be at most 32 Unicode code points")).build();
    }
    private static Response notFound() { return Response.status(404).entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, "notice not found")).build(); }
    private static List<String> splitIds(String ids) { if (ids == null || ids.isBlank()) throw new IllegalArgumentException("ids is required"); return java.util.Arrays.stream(ids.split(",")).map(String::trim).toList(); }
    public record NoticeRequest(String title, String content, String noticeType, Boolean enabled) {}
    public record PublishRequest(JsonNode published) {}
}
