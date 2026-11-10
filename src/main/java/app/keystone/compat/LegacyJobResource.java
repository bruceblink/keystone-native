package app.keystone.compat;

import app.keystone.ApiResponse;
import app.keystone.audit.OperationLogRepository;
import app.keystone.job.Job;
import app.keystone.job.JobInvocationService;
import app.keystone.job.JobLogRepository;
import app.keystone.job.JobService;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;

@Path("/system/jobs")
@Produces(MediaType.APPLICATION_JSON)
@RolesAllowed("ADMIN")
public class LegacyJobResource {
    @Inject JobService service;
    @Inject OperationLogRepository logs;
    @Inject SecurityIdentity identity;

    @GET public ApiResponse<List<Job>> list() { return ApiResponse.ok(service.jobs()); }
    @GET @Path("/{id}") public Response get(@PathParam("id") long id) { try { return Response.ok(ApiResponse.ok(service.jobs().stream().filter(v -> v.id() == id).findFirst().orElseThrow())).build(); } catch (java.util.NoSuchElementException e) { return notFound(); } }
    @GET @Path("/invoke-targets") public ApiResponse<List<JobInvocationService.JobTarget>> targets() { return ApiResponse.ok(service.targets()); }
    @GET @Path("/logs") public ApiResponse<JobLogRepository.Page> logs(@QueryParam("jobId") Long jobId, @QueryParam("page") Integer page, @QueryParam("size") Integer size) { return ApiResponse.ok(service.logs(jobId, page == null ? 1 : page, size == null ? 20 : size)); }
    @POST @Consumes(MediaType.APPLICATION_JSON) public Response create(JobCommand request) { if (request == null) return bad("request body is required"); try { var job = service.create(request.code, request.name, request.group, request.invokeTarget, request.jobParams, request.cron, request.concurrent, request.enabled, request.remark); logs.record(actor(), "CREATE", "job", String.valueOf(job.id()), job.code()); return Response.status(Response.Status.CREATED).entity(ApiResponse.ok(job)).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @PUT @Path("/{id}") @Consumes(MediaType.APPLICATION_JSON) public Response update(@PathParam("id") long id, JobCommand request) { if (request == null) return bad("request body is required"); try { return Response.ok(ApiResponse.ok(service.update(id, request.name, request.group, request.invokeTarget, request.jobParams, request.cron, request.concurrent, request.enabled, request.remark))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } catch (java.util.NoSuchElementException e) { return notFound(); } }
    @PUT @Path("/{id}/status") @Consumes(MediaType.APPLICATION_JSON) public Response status(@PathParam("id") long id, StatusCommand request) { if (request == null || request.enabled == null) return bad("status is required"); try { return Response.ok(ApiResponse.ok(service.update(id, null, null, null, null, null, null, request.enabled, null))).build(); } catch (java.util.NoSuchElementException e) { return notFound(); } }
    @POST @Path("/{id}/run") public Response run(@PathParam("id") long id) { try { service.trigger(id); return Response.ok(ApiResponse.ok(java.util.Map.of("triggered", true))).build(); } catch (java.util.NoSuchElementException e) { return notFound(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }
    @DELETE public Response delete(@QueryParam("jobIds") String jobIds) { if (jobIds == null || jobIds.isBlank()) return bad("jobIds is required"); try { int count = 0; for (Long id : parseIds(jobIds)) { service.delete(id); count++; } return Response.ok(ApiResponse.ok(java.util.Map.of("deleted", count))).build(); } catch (IllegalArgumentException e) { return bad(e.getMessage()); } }

    private String actor() { return identity.getPrincipal().getName(); }
    private static List<Long> parseIds(String value) { try { return Arrays.stream(value.split(",")).map(String::trim).map(Long::valueOf).toList(); } catch (Exception e) { throw new IllegalArgumentException("jobIds must be comma separated numbers"); } }
    private static Response bad(String message) { return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse.error(message)).build(); }
    private static Response notFound() { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("job not found")).build(); }
    public record JobCommand(String code, String name, String group, String invokeTarget, String jobParams, String cron, Boolean concurrent, Boolean enabled, String remark) {}
    public record StatusCommand(Boolean enabled) {}
}
