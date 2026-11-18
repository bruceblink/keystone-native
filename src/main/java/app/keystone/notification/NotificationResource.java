package app.keystone.notification;

import app.keystone.ApiResponse;
import app.keystone.ErrorCode;
import app.keystone.auth.AuthorizationService;
import app.keystone.auth.RejectApiKey;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.NoSuchElementException;

/** 提供只读当前用户收件箱和幂等已读操作，不读取公开公告。 */
@Path("/v1/notifications")
@Produces(MediaType.APPLICATION_JSON)
@Authenticated
@RejectApiKey
public class NotificationResource {
    @Inject NotificationRepository notifications;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    /** 列表和未读数都只针对已认证的人类用户。 */
    @GET
    public ApiResponse<NotificationInbox> list(@QueryParam("page") String page) {
        String recipientUserId = currentUserId();
        if (page == null) return ApiResponse.ok(notifications.listForUser(recipientUserId));
        return ApiResponse.ok(notifications.listForUser(recipientUserId, parsePage(page)));
    }

    /** 详情查询不会暴露其他用户是否拥有指定 ID。 */
    @GET
    @Path("/{id}")
    public Response get(@PathParam("id") String id) {
        try {
            return Response.ok(ApiResponse.ok(notifications.findForUser(currentUserId(), id))).build();
        } catch (NoSuchElementException missing) {
            return notFound();
        }
    }

    /** 只标记当前用户自己的记录，并返回与详情接口相同的 DTO。 */
    @POST
    @Path("/{id}/read")
    public Response read(@PathParam("id") String id) {
        try {
            return Response.ok(ApiResponse.ok(notifications.markReadForUser(currentUserId(), id))).build();
        } catch (NoSuchElementException missing) {
            return notFound();
        }
    }

    private String currentUserId() {
        return authorization.context(identity).subjectId();
    }

    /** 页码异常时回到首页，保持与 Phoenix 的通知列表查询行为一致。 */
    private static int parsePage(String value) {
        try {
            int page = Integer.parseInt(value.strip());
            return page >= 1 && page <= 1_000_000 ? page : 1;
        } catch (NumberFormatException invalidPage) {
            return 1;
        }
    }

    private static Response notFound() {
        return Response.status(Response.Status.NOT_FOUND)
                .entity(ApiResponse.error(ErrorCode.RESOURCE_NOT_FOUND, "notification not found"))
                .build();
    }
}
