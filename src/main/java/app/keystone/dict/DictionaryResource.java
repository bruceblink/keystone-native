package app.keystone.dict;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.RequiresPermission;
import jakarta.inject.Inject;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/dictionaries")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("dictionary")
public class DictionaryResource {
    @Inject DictionaryRepository dictionaries;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET @RequiresPermission("dictionary:read")
    public ApiResponse<List<DictionaryType>> types() { return ApiResponse.ok(dictionaries.types()); }
    @GET @Path("/{typeCode}/items") @RequiresPermission("dictionary:read")
    public ApiResponse<List<DictionaryItem>> items(@PathParam("typeCode") String typeCode) { return ApiResponse.ok(dictionaries.items(typeCode)); }

    @POST @RequiresPermission("dictionary:create")
    public Response createType(TypeRequest request) {
        if (request == null) return bad("request body is required");
        try { var created = dictionaries.createType(request.code(), request.name()); logs.record(actor(), "CREATE", "dictionary-type", String.valueOf(created.id()), created.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(created)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @POST @Path("/{typeCode}/items") @RequiresPermission("dictionary:create")
    public Response createItem(@PathParam("typeCode") String typeCode, ItemRequest request) {
        if (request == null) return bad("request body is required");
        try { var created = dictionaries.createItem(typeCode, request.value(), request.label(), request.sortOrder()); logs.record(actor(), "CREATE", "dictionary-item", String.valueOf(created.id()), created.typeCode() + ":" + created.value()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(created)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @PUT @Path("/types/{code}") @RequiresPermission("dictionary:update")
    public Response updateType(@PathParam("code") String code, TypeRequest request) { if (request == null) return bad("request body is required"); try { var type = dictionaries.updateType(code, request.name(), request.enabled()); logs.record(actor(), "UPDATE", "dictionary-type", String.valueOf(type.id()), type.code()); return Response.ok(ApiResponse.ok(type)).build(); } catch (java.util.NoSuchElementException e) { return notFoundType(); } }

    @DELETE @Path("/types/{code}") @RequiresPermission("dictionary:delete")
    public Response deleteType(@PathParam("code") String code) { try { dictionaries.deleteType(code); logs.record(actor(), "DELETE", "dictionary-type", code, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (java.util.NoSuchElementException e) { return notFoundType(); } }

    @PUT @Path("/items/{id}") @RequiresPermission("dictionary:update")
    public Response updateItem(@PathParam("id") String id, ItemRequest request) { if (request == null) return bad("request body is required"); try { var item = dictionaries.updateItem(id, request.label(), request.sortOrder(), request.enabled()); logs.record(actor(), "UPDATE", "dictionary-item", id, item.value()); return Response.ok(ApiResponse.ok(item)).build(); } catch (java.util.NoSuchElementException | IllegalArgumentException e) { return notFound(); } }

    @DELETE @Path("/items/{id}") @RequiresPermission("dictionary:delete")
    public Response deleteItem(@PathParam("id") String id) {
        try { dictionaries.deleteItem(id); logs.record(actor(), "DELETE", "dictionary-item", id, null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (java.util.NoSuchElementException | IllegalArgumentException e) { return notFound(); }
    }

    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("dictionary item not found")).build(); }
    private static Response notFoundType() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("dictionary type not found")).build(); }
    public record TypeRequest(String code, String name, Boolean enabled) {}
    public record ItemRequest(String value, String label, Integer sortOrder, Boolean enabled) {}
    private String actor() { return identity.getPrincipal().getName(); }
}
