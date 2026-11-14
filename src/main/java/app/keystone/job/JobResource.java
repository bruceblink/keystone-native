package app.keystone.job;

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
import java.util.List;

@Path("/v1/jobs")
@Produces(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("job")
public class JobResource {
    @Inject JobService service;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;
    @Inject AuthorizationService authorization;

    @GET @RequiresPermission("job:read") public ApiResponse<List<Job>> list() { return ApiResponse.ok(service.jobs(context())); }

    @GET @Path("/{id}") @RequiresPermission("job:read")
    public Response get(@PathParam("id") String id) {
        try { return Response.ok(ApiResponse.ok(service.jobs(context()).stream().filter(j -> j.id().equals(id)).findFirst().orElseThrow())).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @GET @Path("/invoke-targets") @RequiresPermission("job:read")
    public ApiResponse<List<JobInvocationService.JobTarget>> targets() { return ApiResponse.ok(service.targets(context())); }

    @GET @Path("/logs") @RequiresPermission("job:read")
    public ApiResponse<JobLogRepository.Page> logs(@QueryParam("jobId") String jobId, @QueryParam("page") Integer page, @QueryParam("size") Integer size) {
        return ApiResponse.ok(service.logs(context(), jobId, page == null ? 1 : page, size == null ? 20 : size));
    }

    @POST @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("job:create")
    public Response create(JobRequest request) {
        if (request == null) return bad("request body is required");
        try {
            var job = service.create(context(), request.code(), request.name(), request.group(), request.invokeTarget(), request.jobParams(), request.cron(), request.concurrent(), request.enabled(), request.remark());
            logs.record(actor(), "CREATE", "job", String.valueOf(job.id()), job.code());
            return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(job)).build();
        } catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @PUT @Path("/{id}") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("job:update")
    public Response update(@PathParam("id") String id, JobRequest request) {
        if (request == null) return bad("request body is required");
        try {
            var job = service.update(context(), id, request.name(), request.group(), request.invokeTarget(), request.jobParams(), request.cron(), request.concurrent(), request.enabled(), request.remark());
            logs.record(actor(), "UPDATE", "job", String.valueOf(id), job.code());
            return Response.ok(ApiResponse.ok(job)).build();
        } catch (IllegalArgumentException e) { return bad(e.getMessage()); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @PUT @Path("/{id}/status") @Consumes(MediaType.APPLICATION_JSON) @RequiresPermission("job:update-status")
    public Response status(@PathParam("id") String id, StatusRequest request) {
        if (request == null || request.enabled() == null) return bad("enabled is required");
        try {
            var job = service.update(context(), id, null, null, null, null, null, null, request.enabled(), null);
            logs.record(actor(), "UPDATE", "job-status", String.valueOf(id), String.valueOf(request.enabled()));
            return Response.ok(ApiResponse.ok(job)).build();
        } catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @POST @Path("/{id}/trigger") @RequiresPermission("job:run")
    public Response trigger(@PathParam("id") String id) { return run(id); }

    @POST @Path("/{id}/run") @RequiresPermission("job:run")
    public Response run(@PathParam("id") String id) {
        try { service.trigger(context(), id); logs.record(actor(), "TRIGGER", "job", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("triggered", true))).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
        catch (IllegalArgumentException e) { return bad(e.getMessage()); }
    }

    @DELETE @Path("/{id}") @RequiresPermission("job:delete")
    public Response delete(@PathParam("id") String id) {
        try { service.delete(context(), id); logs.record(actor(), "DELETE", "job", String.valueOf(id), null); return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", true))).build(); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    @DELETE @RequiresPermission("job:delete")
    public Response deleteBatch(@QueryParam("jobIds") String jobIds, @QueryParam("ids") String ids) {
        String rawIds = firstNonBlank(jobIds, ids);
        try {
            int deleted = service.deleteAll(context(), splitIds(rawIds));
            logs.record(actor(), "DELETE", "jobs", null, "batch deleted=" + deleted);
            return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", deleted))).build();
        } catch (IllegalArgumentException e) { return bad("ids must be comma separated UUIDs"); }
        catch (java.util.NoSuchElementException e) { return notFound(); }
    }

    private String actor() { return identity.getPrincipal().getName(); }
    private AuthorizationContext context() { return authorization.context(identity); }
    private static Response bad(String message) { return Response.status(422).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("job not found")).build(); }
    private static String firstNonBlank(String primary, String fallback) { return primary == null || primary.isBlank() ? fallback : primary; }
    private static List<String> splitIds(String ids) { if (ids == null || ids.isBlank()) throw new IllegalArgumentException("ids is required"); return java.util.Arrays.stream(ids.split(",")).map(String::trim).toList(); }
    public record JobRequest(String code, String name, String group, String invokeTarget, String jobParams, String cron, Boolean concurrent, Boolean enabled, String remark) {}
    public record StatusRequest(Boolean enabled) {}
}
