package app.keystone.auth;

import java.util.Set;

/**
 * 已完成认证和范围解析的调用主体。
 *
 * <p>构造函数和系统能力标记均不可由外部调用方伪造。业务命令只接收此值，不直接读取
 * HTTP 的 SecurityIdentity。</p>
 */
public final class AuthorizationContext {
    private static final Object SYSTEM_CAPABILITY = new Object();

    private final String subjectId;
    private final String username;
    private final String credentialType;
    private final Object capability;
    private final Set<String> permissions;
    private final boolean allScope;
    private final boolean selfScope;
    private final DataScopeService.Scope scope;

    private AuthorizationContext(String subjectId, String username, String credentialType, Object capability,
                                 Set<String> permissions, DataScopeService.Scope scope) {
        this.subjectId = subjectId;
        this.username = username;
        this.credentialType = credentialType;
        this.capability = capability;
        this.permissions = Set.copyOf(permissions == null ? Set.of() : permissions);
        this.scope = scope == null ? DataScopeService.Scope.none() : scope;
        this.allScope = this.scope.all();
        this.selfScope = this.scope.self();
    }

    /** 创建内部系统主体；只有固定能力标记可以满足系统主体判断。 */
    public static AuthorizationContext system() {
        return new AuthorizationContext("system", "system", "SYSTEM", SYSTEM_CAPABILITY, Set.of("*"), DataScopeService.Scope.unrestricted());
    }

    static AuthorizationContext user(String subjectId, String username, String credentialType,
                                    Set<String> permissions, DataScopeService.Scope scope) {
        return new AuthorizationContext(subjectId, username, credentialType, new Object(), permissions, scope);
    }

    public String subjectId() { return subjectId; }
    public String username() { return username; }
    public String credentialType() { return credentialType; }
    public boolean isSystem() { return capability == SYSTEM_CAPABILITY; }
    public boolean allScope() { return allScope; }
    public boolean selfScope() { return selfScope; }
    public DataScopeService.Scope scope() { return scope; }
    public boolean hasPermission(String permission) { return isSystem() || permissions.contains(permission); }
}
