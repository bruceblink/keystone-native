package app.keystone.menu;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

@Path("/v1/menus")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class MenuResource {
    @Inject MenuRepository menus;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET public ApiResponse<List<MenuNode>> tree() { return ApiResponse.ok(toTree(menus.listForRoles(identity.getRoles().stream().toList()))); }

    @POST @RolesAllowed("ADMIN") public Response create(MenuRepository.MenuRequest request) { if (request == null) return bad("request body is required"); try { var menu = menus.create(request); logs.record(actor(), "CREATE", "menu", String.valueOf(menu.id()), menu.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(menu)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @RolesAllowed("ADMIN") public Response update(@PathParam("id") long id, MenuRepository.MenuRequest request) { if (request == null) return bad("request body is required"); try { var menu = menus.update(id, request); logs.record(actor(), "UPDATE", "menu", String.valueOf(id), menu.code()); return Response.ok(ApiResponse.ok(menu)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }
    @PUT @Path("/{id}/roles") @RolesAllowed("ADMIN") public Response assignRoles(@PathParam("id") long id, RoleAssignment request) { if (request == null) return bad("request body is required"); try { menus.assignRoles(id, request.roleCodes()); logs.record(actor(), "UPDATE", "menu-role", String.valueOf(id), null); return Response.ok(ApiResponse.ok(Map.of("updated", true))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @DELETE @Path("/{id}") @RolesAllowed("ADMIN") public Response delete(@PathParam("id") long id) { try { menus.delete(id); logs.record(actor(), "DELETE", "menu", String.valueOf(id), null); return Response.ok(ApiResponse.ok(Map.of("deleted", true))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (NoSuchElementException e) { return notFound(); } }

    private List<MenuNode> toTree(List<Menu> items) { Map<Long, MenuNodeBuilder> nodes = items.stream().collect(Collectors.toMap(Menu::id, MenuNodeBuilder::new, (a, b) -> a, LinkedHashMap::new)); List<MenuNodeBuilder> roots = new ArrayList<>(); for (Menu menu : items) { var node = nodes.get(menu.id()); if (menu.parentId() == null || !nodes.containsKey(menu.parentId())) roots.add(node); else nodes.get(menu.parentId()).children.add(node); } return roots.stream().map(MenuNodeBuilder::build).toList(); }
    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("menu not found")).build(); }
    private static final class MenuNodeBuilder { final Menu menu; final List<MenuNodeBuilder> children = new ArrayList<>(); MenuNodeBuilder(Menu menu) { this.menu = menu; } MenuNode build() { return new MenuNode(menu, children.stream().map(MenuNodeBuilder::build).toList()); } }
    public record RoleAssignment(List<String> roleCodes) {}
}
