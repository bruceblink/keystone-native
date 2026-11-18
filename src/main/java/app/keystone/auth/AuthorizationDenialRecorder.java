package app.keystone.auth;

import app.keystone.audit.SecurityEventContext;
import app.keystone.audit.SecurityEventRepository;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/** 统一记录权限拒绝事件，保留主体、凭据和请求关联信息，不保存认证秘密。 */
@ApplicationScoped
public class AuthorizationDenialRecorder {
    @Inject SecurityEventRepository securityEvents;
    @Inject ClientAddressResolver clientAddresses;

    /** 记录拒绝原因；审计存储故障不改变原授权响应。 */
    public void record(SecurityIdentity identity, RoutingContext routingContext, String permission, String detail) {
        try {
            String actor = identity == null || identity.isAnonymous() ? null : identity.getPrincipal().getName();
            Object credentialValue = identity == null || identity.isAnonymous() ? null : identity.getAttribute("credentialType");
            String credential = credentialValue == null ? null : String.valueOf(credentialValue);
            Object credentialIdValue = identity == null || identity.isAnonymous() ? null : identity.getAttribute("credentialId");
            String credentialId = credentialIdValue == null ? null : String.valueOf(credentialIdValue);
            String forwardedFor = routingContext == null || routingContext.request() == null
                    ? null : routingContext.request().getHeader("X-Forwarded-For");
            String sourceIp = clientAddresses.resolve(routingContext, forwardedFor);
            securityEvents.record("AUTHORIZATION", actor, credential, credentialId, sourceIp,
                    "permission", permission, "DENIED", SecurityEventContext.from(identity, routingContext), detail);
        } catch (IllegalStateException ignored) {
            // 审计存储故障不改变原授权拒绝结果。
        }
    }
}
