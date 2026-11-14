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

    private AuthorizationContext(String subjectId, String username, String credentialType, Object capability,
                                 Set<String> permissions, boolean allScope, boolean selfScope) {
        this.subjectId = subjectId;
        this.username = username;
        this.credentialType = credentialType;
        this.capability = capability;
        this.permissions = Set.copyOf(permissions == null ? Set.of() : permissions);
        this.allScope = allScope;
        this.selfScope = selfScope;
    }

    /** 创建内部系统主体；只有固定能力标记可以满足系统主体判断。 */
    public static AuthorizationContext system() {
        return new AuthorizationContext("system", "system", "SYSTEM", SYSTEM_CAPABILITY, Set.of("*"), true, false);
    }

    static AuthorizationContext user(String subjectId, String username, String credentialType,
                                    Set<String> permissions, boolean allScope, boolean selfScope) {
        return new AuthorizationContext(subjectId, username, credentialType, new Object(), permissions, allScope, selfScope);
    }

    public String subjectId() { return subjectId; }
    public String username() { return username; }
    public String credentialType() { return credentialType; }
    public boolean isSystem() { return capability == SYSTEM_CAPABILITY; }
    public boolean allScope() { return allScope; }
    public boolean selfScope() { return selfScope; }
    public boolean hasPermission(String permission) { return isSystem() || permissions.contains(permission); }
}
