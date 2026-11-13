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

    private static final Set<String> VALUES = Set.of(
            ALL, TENANT, SELF, DEPARTMENT, DEPARTMENT_AND_CHILDREN, CUSTOM, OWNER, MEMBER);
    private static final Map<String, Set<String>> RESOURCE_SCOPES = Map.of(
            "user", Set.of(ALL, TENANT, SELF, DEPARTMENT, DEPARTMENT_AND_CHILDREN, CUSTOM),
            "department", Set.of(ALL, TENANT, DEPARTMENT, DEPARTMENT_AND_CHILDREN, CUSTOM),
            "owned", Set.of(ALL, OWNER, MEMBER));

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
        return resource != null && RESOURCE_SCOPES.getOrDefault(resource, Set.of()).contains(normalize(value));
    }
}
