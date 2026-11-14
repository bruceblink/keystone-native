package app.keystone.menu;

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
import java.util.*;
import java.util.stream.Collectors;

@Path("/v1/menus")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("menu")
public class MenuResource {
    @Inject MenuRepository menus;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @RequiresPermission("menu:read") public ApiResponse<List<MenuNode>> tree() { return ApiResponse.ok(toTree(menus.listForRoles(context(), identity.getRoles().stream().toList()))); }
    @GET @Path("/dropdown") @RequiresPermission("menu:read") public ApiResponse<List<Menu>> dropdown() { return ApiResponse.ok(menus.listForRoles(context(), identity.getRoles().stream().toList())); }

    @POST @RequiresPermission("menu:create") public Response create(MenuRepository.MenuRequest request) { if (request == null) return bad("request body is required"); try { var menu = menus.create(context(), request); logs.record(actor(), "CREATE", "menu", String.valueOf(menu.id()), menu.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(menu)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RequiresPermission("menu:update") public Response update(@PathParam("id") String id, MenuRepository.MenuRequest request) { if (request == null) return bad("request body is required"); try { var menu = menus.update(context(), id, request); logs.record(actor(), "UPDATE", "menu", id, menu.code()); return Response.ok(ApiResponse.ok(menu)).build(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } catch (NoSuchElementException e) { return notFound(); } }
    @PUT @Path("/{id}/roles") @RequiresPermission("menu:manage") public Response assignRoles(@PathParam("id") String id, RoleAssignment request) { if (request == null) return bad("request body is required"); try { menus.assignRoles(context(), id, request.roleCodes()); logs.record(actor(), "UPDATE", "menu-role", id, null); return Response.ok(ApiResponse.ok(Map.of("updated", true))).build(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } }
    @DELETE @Path("/{id}") @RequiresPermission("menu:delete") public Response delete(@PathParam("id") String id) { try { menus.delete(context(), id); logs.record(actor(), "DELETE", "menu", id, null); return Response.ok(ApiResponse.ok(Map.of("deleted", true))).build(); } catch (IllegalArgumentException e) { return bad("id must be a UUID"); } catch (NoSuchElementException e) { return notFound(); } }

    private AuthorizationContext context() { return authorization.context(identity); }
    private List<MenuNode> toTree(List<Menu> items) { Map<String, MenuNodeBuilder> nodes = items.stream().collect(Collectors.toMap(Menu::id, MenuNodeBuilder::new, (a, b) -> a, LinkedHashMap::new)); List<MenuNodeBuilder> roots = new ArrayList<>(); for (Menu menu : items) { var node = nodes.get(menu.id()); if (menu.parentId() == null || !nodes.containsKey(menu.parentId())) roots.add(node); else nodes.get(menu.parentId()).children.add(node); } return roots.stream().map(MenuNodeBuilder::build).toList(); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("menu not found")).build(); }
    private static final class MenuNodeBuilder { final Menu menu; final List<MenuNodeBuilder> children = new ArrayList<>(); MenuNodeBuilder(Menu menu) { this.menu = menu; } MenuNode build() { return new MenuNode(menu, children.stream().map(MenuNodeBuilder::build).toList()); } }
    public record RoleAssignment(List<String> roleCodes) {}
}
