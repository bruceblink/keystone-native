package app.keystone.auth;

import app.keystone.ApiResponse;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.Comparator;
import java.util.List;

/** 提供 API Key 签发主体可读取的动态权限目录；目录项不改变权限，只描述当前主体可授予的范围。 */
@Path("/v1/permissions")
@Produces(MediaType.APPLICATION_JSON)
public class PermissionCatalogResource {
    @Inject AuthorizationService authorization;
    @Inject SecurityIdentity identity;

    /** 返回完整目录；能签发 API Key 的主体可以读取，并获得每项 scope 的可授予标记。 */
    @GET
    @Path("/catalog")
    @RequiresPermission("api-key:create")
    public ApiResponse<CatalogResponse> catalog() {
        List<Entry> entries = PermissionCatalog.values().stream()
                .sorted(Comparator.naturalOrder())
                .map(permission -> entry(permission, authorization.allowed(identity, permission)))
                .toList();
        return ApiResponse.ok(new CatalogResponse(entries));
    }

    private static Entry entry(String permission, boolean allowed) {
        String[] parts = permission.split(":", 2);
        String resource = parts[0];
        String action = parts[1];
        return new Entry(permission, resource, action, resource + " " + action, risk(action), true, allowed);
    }

    private static String risk(String action) {
        if (action.equals("delete") || action.equals("revoke") || action.equals("reset-password") || action.equals("manage")) {
            return "high";
        }
        if (action.equals("create") || action.equals("update") || action.equals("update-status")
                || action.equals("run") || action.equals("rotate") || action.equals("import") || action.equals("export")) {
            return "medium";
        }
        return "low";
    }

    public record CatalogResponse(List<Entry> entries) { }

    public record Entry(String permission, String resource, String action, String description,
                         String risk, boolean registered, boolean allowed) { }
}
