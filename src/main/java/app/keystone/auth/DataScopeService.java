package app.keystone.auth;

import app.keystone.dept.DepartmentOrmRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.util.LinkedHashSet;
import java.util.Set;

/** 读取主体的数据范围，并把角色范围合并为一次请求使用的策略。 */
@ApplicationScoped
public class DataScopeService {
    private static final int DEPARTMENT_BATCH_SIZE = 500;

    @Inject ApiKeyUserRepository users;
    @Inject DepartmentOrmRepository departments;

    /** 在一个 ORM 事务内读取用户和角色，避免范围计算使用不同数据快照。 */
    @Transactional
    public Scope forUser(String userId) {
        try {
            ApiKeyUserEntity user = users.findEnabledEntity(userId);
            if (user == null) return Scope.none();
            String ownDepartment = user.departmentId();
            boolean all = false;
            boolean self = false;
            boolean owner = false;
            var allowedDepartments = new LinkedHashSet<String>();
            for (ApiKeyRoleEntity role : user.roles()) {
                if (!role.enabled()) continue;
                switch (normalizeScope(role.dataScope())) {
                    case DataScopePolicy.ALL, DataScopePolicy.TENANT -> all = true;
                    case "SELF" -> self = true;
                    case DataScopePolicy.OWNER -> owner = true;
                    case "DEPARTMENT" -> addIfPresent(allowedDepartments, ownDepartment);
                    case "DEPARTMENT_AND_CHILDREN" -> allowedDepartments.addAll(descendants(ownDepartment));
                    case "CUSTOM" -> allowedDepartments.addAll(parseDepartments(role.deptScope()));
                    default -> throw new IllegalStateException("Unsupported data scope");
                }
            }
            return new Scope(all, self, owner, allowedDepartments, ownDepartment);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not resolve user data scope", e);
        }
    }


    private Set<String> descendants(String departmentId) {
        if (departmentId == null) return Set.of();
        var result = new LinkedHashSet<String>();
        var frontier = new LinkedHashSet<String>();
        frontier.add(departmentId);
        result.add(departmentId);
        while (!frontier.isEmpty()) {
            var next = new LinkedHashSet<String>();
            var parents = new java.util.ArrayList<>(frontier);
            for (int start = 0; start < parents.size(); start += DEPARTMENT_BATCH_SIZE) {
                int end = Math.min(start + DEPARTMENT_BATCH_SIZE, parents.size());
                var batch = new LinkedHashSet<>(parents.subList(start, end));
                for (String child : departments.findChildIds(batch)) {
                    if (result.add(child)) next.add(child);
                }
            }
            frontier = next;
        }
        return result;
    }

    private static String normalizeScope(String value) {
        String normalized = value == null || value.isBlank() ? DataScopePolicy.ALL : DataScopePolicy.normalize(value);
        if (!DataScopePolicy.registered(normalized)) throw new IllegalStateException("Unsupported data scope");
        return normalized;
    }

    private static void addIfPresent(Set<String> target, String value) {
        if (value != null) target.add(value);
    }

    /** 解析 CUSTOM 部门 ID；格式错误直接失败，不能扩大为全部范围。 */
    private static Set<String> parseDepartments(String value) {
        var result = new LinkedHashSet<String>();
        if (value == null || value.isBlank()) return result;
        for (String item : value.split("[,\\s]+")) {
            try { result.add(app.keystone.identity.UuidValues.requireCanonical(item.trim())); }
            catch (IllegalArgumentException e) { throw new IllegalStateException("Invalid custom department scope", e); }
        }
        return result;
    }

    /** 范围只允许并集；没有有效角色时返回空范围。 */
    public record Scope(boolean all, boolean self, boolean owner, Set<String> departments, String ownDepartment) {
        public Scope {
            departments = Set.copyOf(departments == null ? Set.of() : departments);
        }

        /** 保留用户和部门范围构造方式；owner 只用于具有所有者关系的资源。 */
        public Scope(boolean all, boolean self, Set<String> departments, String ownDepartment) {
            this(all, self, false, departments, ownDepartment);
        }

        public Scope(boolean all, boolean self, Set<String> departments) {
            this(all, self, false, departments, null);
        }

        public static Scope none() {
            return new Scope(false, false, false, Set.of(), null);
        }

        public static Scope unrestricted() {
            return new Scope(true, false, false, Set.of(), null);
        }

        public boolean allowsUser(String subjectId, String targetId, String targetDepartment) {
            return all || (self && subjectId != null && subjectId.equals(targetId)) || targetDepartment != null && departments.contains(targetDepartment);
        }

        public boolean allowsDepartment(String departmentId) {
            return all || departmentId != null && ((self && departmentId.equals(ownDepartment)) || departments.contains(departmentId));
        }


        /** 判断新建部门时的父部门是否在当前主体的写入范围内。 */
        public boolean allowsDepartmentCreation(String parentDepartmentId) {
            return all || parentDepartmentId != null && allowsDepartment(parentDepartmentId);
        }


        /** 判断更新部门时目标部门和新的父部门是否都在当前主体的写入范围内。 */
        public boolean allowsDepartmentUpdate(String targetDepartmentId, String parentDepartmentId) {
            return allowsDepartment(targetDepartmentId)
                    && (parentDepartmentId == null || allowsDepartment(parentDepartmentId));
        }


        public boolean isEmpty() {
            return !all && !self && !owner && departments.isEmpty();
        }
    }
}
