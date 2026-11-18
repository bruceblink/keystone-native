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
    private final String subjectType;
    private final String username;
    private final String credentialType;
    private final String credentialId;
    private final String clientId;
    private final Object capability;
    private final Set<String> permissions;
    private final Set<String> approvedScopes;
    private final String dataScope;
    private final long permissionVersion;
    private final String authenticationLevel;
    private final boolean allScope;
    private final boolean selfScope;
    private final boolean ownerScope;
    private final DataScopeService.Scope scope;

    private AuthorizationContext(String subjectId, String subjectType, String username, String credentialType,
                                 String credentialId, String clientId, Object capability, Set<String> permissions,
                                 Set<String> approvedScopes, String dataScope, long permissionVersion,
                                 String authenticationLevel, DataScopeService.Scope scope) {
        this.subjectId = subjectId;
        this.subjectType = subjectType;
        this.username = username;
        this.credentialType = credentialType;
        this.credentialId = credentialId;
        this.clientId = clientId;
        this.capability = capability;
        this.permissions = Set.copyOf(permissions == null ? Set.of() : permissions);
        this.approvedScopes = Set.copyOf(approvedScopes == null ? Set.of() : approvedScopes);
        this.dataScope = dataScope == null || dataScope.isBlank() ? "NONE" : dataScope;
        this.permissionVersion = permissionVersion;
        this.authenticationLevel = authenticationLevel == null || authenticationLevel.isBlank() ? "AAL1" : authenticationLevel;
        this.scope = scope == null ? DataScopeService.Scope.none() : scope;
        this.allScope = this.scope.all();
        this.selfScope = this.scope.self();
        this.ownerScope = this.scope.owner();
    }

    /** 创建内部系统主体；只有固定能力标记可以满足系统主体判断。 */
    public static AuthorizationContext system() {
        return new AuthorizationContext("system", "SYSTEM", "system", "SYSTEM", "system", "system",
                SYSTEM_CAPABILITY, Set.of("*"), Set.of("*"), "ALL", Long.MAX_VALUE, "SYSTEM",
                DataScopeService.Scope.unrestricted());
    }

    static AuthorizationContext user(String subjectId, String username, String credentialType,
                                    Set<String> permissions, DataScopeService.Scope scope) {
        return user(subjectId, "USER", username, credentialType, null, "web", permissions, permissions,
                dataScope(scope), 0, "AAL1", scope);
    }

    static AuthorizationContext user(String subjectId, String subjectType, String username, String credentialType,
                                    String credentialId, String clientId, Set<String> permissions,
                                    Set<String> approvedScopes, String dataScope, long permissionVersion,
                                    String authenticationLevel, DataScopeService.Scope scope) {
        return new AuthorizationContext(subjectId, subjectType, username, credentialType, credentialId, clientId,
                new Object(), permissions, approvedScopes, dataScope, permissionVersion, authenticationLevel, scope);
    }

    public String subjectId() { return subjectId; }
    public String subjectType() { return subjectType; }
    public String username() { return username; }
    public String credentialType() { return credentialType; }
    public String credentialId() { return credentialId; }
    public String clientId() { return clientId; }
    public Set<String> approvedScopes() { return approvedScopes; }
    public String dataScope() { return dataScope; }
    public long permissionVersion() { return permissionVersion; }
    public String authenticationLevel() { return authenticationLevel; }
    public boolean isSystem() { return capability == SYSTEM_CAPABILITY; }
    public boolean allScope() { return allScope; }
    public boolean selfScope() { return selfScope; }
    public boolean ownerScope() { return ownerScope; }
    public DataScopeService.Scope scope() { return scope; }
    /** API Key 的有效权限必须同时存在于主体权限和该密钥批准的范围中。 */
    public boolean hasPermission(String permission) {
        return isSystem() || (permissions.contains(permission)
                && (!"API_KEY".equals(credentialType) || approvedScopes.contains(permission)));
    }

    private static String dataScope(DataScopeService.Scope scope) {
        if (scope == null) return "NONE";
        if (scope.all()) return "ALL";
        if (scope.owner()) return "OWNER";
        if (scope.self()) return "SELF";
        return scope.departments().isEmpty() ? "NONE" : "CUSTOM";
    }
}
