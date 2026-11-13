package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.Connection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 读取主体的数据范围，并把角色范围合并为一次请求使用的策略。
 * 该服务只负责范围计算；具体资源仍由数据访问层把策略转换为查询条件。
 */
@ApplicationScoped
public class DataScopeService {
    @Inject DataSource dataSource;

    /** 为当前请求主体读取已启用角色的范围；数据库异常时由调用方按失败关闭处理。 */
    public Scope forUser(long userId) {
        try (var c = dataSource.getConnection()) {
            return readScope(c, userId);
        } catch (Exception e) {
            throw new IllegalStateException("Could not resolve user data scope", e);
        }
    }

    /** 先读取主体部门，再合并每个启用角色的范围；多个角色采用并集。 */
    private Scope readScope(Connection c, long userId) throws Exception {
        Long ownDepartment = null;
        try (var user = c.prepareStatement("SELECT dept_id FROM sys_user WHERE id = ? AND enabled = true")) {
            user.setLong(1, userId);
            try (var rs = user.executeQuery()) {
                if (!rs.next()) return Scope.none();
                long department = rs.getLong(1);
                if (!rs.wasNull()) ownDepartment = department;
            }
        }

        boolean all = false;
        boolean self = false;
        var departments = new LinkedHashSet<Long>();
        String sql = "SELECT r.data_scope, r.dept_scope FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ? AND r.enabled = true";
        try (var roles = c.prepareStatement(sql)) {
            roles.setLong(1, userId);
            try (var rs = roles.executeQuery()) {
                while (rs.next()) {
                    String scope = normalizeScope(rs.getString("data_scope"));
                    switch (scope) {
                        case "ALL" -> all = true;
                        case "SELF" -> self = true;
                        case "DEPARTMENT" -> addIfPresent(departments, ownDepartment);
                        case "DEPARTMENT_AND_CHILDREN" -> departments.addAll(descendants(c, ownDepartment));
                        case "CUSTOM" -> departments.addAll(parseDepartments(rs.getString("dept_scope")));
                        default -> throw new IllegalStateException("Unsupported data scope: " + scope);
                    }
                }
            }
        }
        return new Scope(all, self, departments, ownDepartment);
    }

    private static String normalizeScope(String value) {
        return value == null || value.isBlank() ? "ALL" : value.trim().toUpperCase(java.util.Locale.ROOT);
    }

    private static void addIfPresent(Set<Long> target, Long value) {
        if (value != null) target.add(value);
    }

    /** 解析 CUSTOM 的部门 ID；格式错误直接失败，避免把错误配置扩大为全部范围。 */
    private static Set<Long> parseDepartments(String value) {
        var result = new LinkedHashSet<Long>();
        if (value == null || value.isBlank()) return result;
        for (String item : value.split("[,\\s]+")) {
            try {
                long id = Long.parseLong(item.trim());
                if (id <= 0) throw new NumberFormatException(item);
                result.add(id);
            } catch (NumberFormatException e) {
                throw new IllegalStateException("Invalid custom department scope", e);
            }
        }
        return result;
    }

    /** 使用去重递归查询包含根部门在内的所有子部门，循环关系不会重复返回记录。 */
    private static Set<Long> descendants(Connection c, Long departmentId) throws Exception {
        if (departmentId == null) return Set.of();
        var result = new LinkedHashSet<Long>();
        String sql = "WITH RECURSIVE department_tree AS (SELECT id FROM sys_dept WHERE id = ? UNION SELECT d.id FROM sys_dept d JOIN department_tree t ON d.parent_id = t.id) SELECT id FROM department_tree";
        try (var p = c.prepareStatement(sql)) {
            p.setLong(1, departmentId);
            try (var rs = p.executeQuery()) {
                while (rs.next()) result.add(rs.getLong(1));
            }
        }
        return result;
    }

    /**
     * 范围只允许并集，不允许因为某个角色范围较小而扩大限制。
     * 没有有效角色时返回空范围，调用方必须拒绝所有目标记录。
     */
    public record Scope(boolean all, boolean self, Set<Long> departments, Long ownDepartment) {
        public Scope {
            departments = Set.copyOf(departments == null ? Set.of() : departments);
        }

        public Scope(boolean all, boolean self, Set<Long> departments) {
            this(all, self, departments, null);
        }

        public static Scope none() {
            return new Scope(false, false, Set.of());
        }

        public static Scope unrestricted() {
            return new Scope(true, false, Set.of());
        }

        public boolean allowsUser(long subjectId, long targetId, Long targetDepartment) {
            return all || (self && subjectId == targetId) || targetDepartment != null && departments.contains(targetDepartment);
        }

        public boolean allowsDepartment(Long departmentId) {
            return all || departmentId != null && ((self && departmentId.equals(ownDepartment)) || departments.contains(departmentId));
        }

        public boolean isEmpty() {
            return !all && !self && departments.isEmpty();
        }
    }
}
