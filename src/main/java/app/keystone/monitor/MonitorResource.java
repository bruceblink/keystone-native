package app.keystone.monitor;

import app.keystone.ApiResponse;
import app.keystone.auth.SessionRepository;
import app.keystone.auth.RequiresPermission;
import app.keystone.auth.RequiresMfaStepUp;
import app.keystone.audit.LoginLogRepository;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.Map;

@Path("/v1/monitor")
@Produces(MediaType.APPLICATION_JSON)
@app.keystone.auth.RequiresDataScope("session")
public class MonitorResource {
    @Inject SessionRepository sessions;
    @Inject LoginLogRepository loginLogs;

    @GET @Path("/onlineUsers") @RequiresPermission("session:read")
    public ApiResponse<Page> onlineUsers(@QueryParam("username") String username, @QueryParam("ipAddress") String ipAddress, @QueryParam("page") Integer page, @QueryParam("size") Integer size) {
        List<SessionRepository.OnlineSession> all = sessions.activeSessions(username, ipAddress);
        int safePage = Math.max(1, page == null ? 1 : page), safeSize = Math.min(100, Math.max(1, size == null ? 20 : size));
        int from = Math.min(all.size(), (safePage - 1) * safeSize), to = Math.min(all.size(), from + safeSize);
        return ApiResponse.ok(new Page(all.subList(from, to), safePage, safeSize, all.size()));
    }

    @DELETE @Path("/onlineUser/{sessionId}") @RequiresPermission("session:revoke") @RequiresMfaStepUp
    public Response logout(@PathParam("sessionId") String sessionId) {
        try { sessions.revokeById(sessionId); return Response.ok(ApiResponse.ok(Map.of("loggedOut", true))).build(); }
        catch (java.util.NoSuchElementException e) { return Response.status(Response.Status.NOT_FOUND).entity(ApiResponse.error("session not found")).build(); }
    }

    @GET @Path("/serverInfo") @RequiresPermission("audit:read")
    public ApiResponse<Map<String, Object>> serverInfo() {
        var runtime = Runtime.getRuntime(); var memory = ManagementFactory.getMemoryMXBean();
        return ApiResponse.ok(Map.of("javaVersion", System.getProperty("java.version"), "jvmName", System.getProperty("java.vm.name"), "osName", System.getProperty("os.name"), "osVersion", System.getProperty("os.version"), "processors", runtime.availableProcessors(), "maxMemory", runtime.maxMemory(), "totalMemory", runtime.totalMemory(), "freeMemory", runtime.freeMemory(), "heapUsed", memory.getHeapMemoryUsage().getUsed(), "uptimeMs", ManagementFactory.getRuntimeMXBean().getUptime()));
    }

    @GET @Path("/cacheInfo") @RequiresPermission("audit:read")
    public ApiResponse<Map<String, Object>> cacheInfo() {
        return ApiResponse.ok(Map.of("provider", "database", "activeSessions", sessions.activeSessions(null, null).size(), "loginLogEntries", loginLogs.list(1, 1, null, null).total()));
    }

    public record Page(List<SessionRepository.OnlineSession> items, int page, int size, long total) {}
}
