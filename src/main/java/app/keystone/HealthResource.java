package app.keystone;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/v1/health")
@Produces(MediaType.APPLICATION_JSON)
public class HealthResource {
    @GET
    public ApiResponse<Health> check() { return ApiResponse.ok(new Health("UP", "keystone-native")); }
    public record Health(String status, String service) {}
}
