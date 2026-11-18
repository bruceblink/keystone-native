package app.keystone.auth;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;

/** 为能力接口的成功和失败响应统一禁止缓存。 */
@Provider
@Priority(Priorities.HEADER_DECORATOR)
public class AuthCapabilitiesNoStoreFilter implements ContainerResponseFilter {
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        String path = request.getUriInfo().getPath();
        if (path.endsWith("v1/auth/me/capabilities")) {
            response.getHeaders().putSingle("Cache-Control", "no-store");
        }
    }
}
