package app.keystone.dict;

import app.keystone.ApiResponse;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/dictionaries")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed({"USER", "ADMIN"})
public class DictionaryResource {
    @Inject DictionaryRepository dictionaries;

    @GET public ApiResponse<List<DictionaryType>> types() { return ApiResponse.ok(dictionaries.types()); }
    @GET @Path("/{typeCode}/items") public ApiResponse<List<DictionaryItem>> items(@PathParam("typeCode") String typeCode) { return ApiResponse.ok(dictionaries.items(typeCode)); }

    @POST @RolesAllowed("ADMIN")
    public Response createType(TypeRequest request) {
        if (request == null) return bad("request body is required");
        try { return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(dictionaries.createType(request.code(), request.name()))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @POST @Path("/{typeCode}/items") @RolesAllowed("ADMIN")
    public Response createItem(@PathParam("typeCode") String typeCode, ItemRequest request) {
        if (request == null) return bad("request body is required");
        try { return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(dictionaries.createItem(typeCode, request.value(), request.label(), request.sortOrder()))).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @Path("/items/{id}") @RolesAllowed("ADMIN")
    public Response deleteItem(@PathParam("id") long id) {
        try { dictionaries.deleteItem(id); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("dictionary item not found")).build(); }
    public record TypeRequest(String code, String name) {}
    public record ItemRequest(String value, String label, Integer sortOrder) {}
}
