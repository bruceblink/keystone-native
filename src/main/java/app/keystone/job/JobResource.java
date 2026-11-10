package app.keystone.job;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

@Path("/v1/jobs")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RolesAllowed("ADMIN")
public class JobResource {
    @Inject JobService service;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET public ApiResponse<List<Job>> list() { return ApiResponse.ok(service.jobs()); }

    @POST public Response create(JobRequest request) {
        if (request == null) return bad("request body is required");
        try { var job = service.create(request.code(), request.name(), request.cron()); logs.record(actor(), "CREATE", "job", String.valueOf(job.id()), job.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(job)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") public Response update(@PathParam("id") long id, JobRequest request) {
        if (request == null) return bad("request body is required");
        try { var job = service.update(id, request.name(), request.cron(), request.enabled()); logs.record(actor(), "UPDATE", "job", String.valueOf(id), job.code()); return Response.ok(ApiResponse.ok(job)).build(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @POST @Path("/{id}/trigger") public Response trigger(@PathParam("id") long id) { service.trigger(id); logs.record(actor(), "TRIGGER", "job", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("triggered", true))).build(); }
    @DELETE @Path("/{id}") public Response delete(@PathParam("id") long id) { try { service.delete(id); logs.record(actor(), "DELETE", "job", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); } catch (java.util.NoSuchElementException e) { return notFound(); } }

    private String actor() { return identity.getPrincipal().getName(); }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("job not found")).build(); }
    public record JobRequest(String code, String name, String cron, Boolean enabled) {}
}
