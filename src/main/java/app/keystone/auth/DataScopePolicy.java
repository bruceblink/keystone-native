package app.keystone.auth;

import java.util.Map;
import java.util.Set;

/**
 * 两个项目共用的数据范围目录和资源适用规则。
 * 单租户资源把 TENANT 视为当前租户全部数据；OWNER、MEMBER 只允许在明确提供资源关系的入口使用。
 */
public final class DataScopePolicy {
    public static final String ALL = "ALL";
    public static final String TENANT = "TENANT";
    public static final String SELF = "SELF";
    public static final String DEPARTMENT = "DEPARTMENT";
    public static final String DEPARTMENT_AND_CHILDREN = "DEPARTMENT_AND_CHILDREN";
    public static final String CUSTOM = "CUSTOM";
    public static final String OWNER = "OWNER";
    public static final String MEMBER = "MEMBER";

    /** 资源范围执行方式；查询型资源必须在仓储层加条件，其他资源由入口拒绝越界主体。 */
    public enum Enforcement {
        QUERY_FILTERED,
        OWNER_BOUND,
        ALL_OR_TENANT
    }

    public record ResourceRule(Set<String> scopes, Enforcement enforcement) {
        public ResourceRule {
            scopes = Set.copyOf(scopes);
        }
    }

    private static final Set<String> VALUES = Set.of(
            ALL, TENANT, SELF, DEPARTMENT, DEPARTMENT_AND_CHILDREN, CUSTOM, OWNER, MEMBER);
    private static final Map<String, Set<String>> RESOURCE_SCOPES = Map.of(
            "user", Set.of(ALL, TENANT, SELF, DEPARTMENT, DEPARTMENT_AND_CHILDREN, CUSTOM),
            "department", Set.of(ALL, TENANT, DEPARTMENT, DEPARTMENT_AND_CHILDREN, CUSTOM),
            "owned", Set.of(ALL, OWNER, MEMBER));

    /**
     * 统一资源范围矩阵。
     *
     * <p>QUERY_FILTERED 由用户和部门仓储使用查询条件落实；OWNER_BOUND 只允许全部范围
     * 或本人范围；ALL_OR_TENANT 对没有明确主体关系的资源默认要求全部或租户范围。
     * 单租户部署中 ALL 和 TENANT 都由 Scope.all 表示。</p>
     */
    private static final Map<String, ResourceRule> RESOURCE_RULES = Map.ofEntries(
            Map.entry("user", new ResourceRule(RESOURCE_SCOPES.get("user"), Enforcement.QUERY_FILTERED)),
            Map.entry("department", new ResourceRule(RESOURCE_SCOPES.get("department"), Enforcement.QUERY_FILTERED)),
            Map.entry("profile", new ResourceRule(Set.of(ALL, TENANT, SELF), Enforcement.OWNER_BOUND)),
            Map.entry("api-key", new ResourceRule(Set.of(ALL, TENANT, SELF), Enforcement.OWNER_BOUND)),
            Map.entry("role", globalRule()),
            Map.entry("post", globalRule()),
            Map.entry("menu", globalRule()),
            Map.entry("config", globalRule()),
            Map.entry("dictionary", globalRule()),
            Map.entry("notice", ownerOrGlobalRule()),
            Map.entry("job", ownerOrGlobalRule()),
            Map.entry("file", ownerOrGlobalRule()),
            Map.entry("audit", globalRule()),
            Map.entry("session", globalRule())
    );

    private DataScopePolicy() {
    }

    public static Set<String> values() {
        return VALUES;
    }

    public static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(java.util.Locale.ROOT);
    }

    public static boolean registered(String value) {
        return VALUES.contains(normalize(value));
    }

    public static boolean supported(String resource, String value) {
        return resource != null && RESOURCE_SCOPES.getOrDefault(normalizeResource(resource), Set.of()).contains(normalize(value));
    }

    /** 返回资源执行规则；未知资源必须在入口拒绝，不能默认为全部数据。 */
    public static ResourceRule rule(String resource) {
        return resource == null ? null : RESOURCE_RULES.get(normalizeResource(resource));
    }

    /** 检查主体是否满足资源入口的范围要求。 */
    public static boolean allows(ResourceRule rule, boolean allScope, boolean selfScope) {
        if (rule == null) return false;
        return switch (rule.enforcement()) {
            case QUERY_FILTERED -> true;
            case OWNER_BOUND -> allScope || selfScope;
            case ALL_OR_TENANT -> allScope;
        };
    }

    /** 返回完整矩阵供测试、文档和启动检查使用。 */
    public static Map<String, ResourceRule> resourceRules() {
        return RESOURCE_RULES;
    }

    private static ResourceRule globalRule() {
        return new ResourceRule(Set.of(ALL, TENANT), Enforcement.ALL_OR_TENANT);
    }

    private static ResourceRule ownerOrGlobalRule() {
        // 当前模型未保存这些资源的稳定 owner/member 关系，先采用默认拒绝的全量范围规则。
        return new ResourceRule(Set.of(ALL, TENANT), Enforcement.ALL_OR_TENANT);
    }

    private static String normalizeResource(String value) {
        return value.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
