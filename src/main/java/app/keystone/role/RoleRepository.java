package app.keystone.role;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

@ApplicationScoped
public class RoleRepository {
    @Inject DataSource dataSource;

    public List<Role> list() {
        String sql = select("ORDER BY r.code");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql); var rs = p.executeQuery()) { var roles = new ArrayList<Role>(); while (rs.next()) roles.add(toRole(rs)); return roles; }
        catch (Exception e) { throw new IllegalStateException("Could not list roles", e); }
    }

    public Role create(String code, String name) {
        require(code, "code"); require(name, "name");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_role(code, name) VALUES (?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, code.trim()); p.setString(2, name.trim()); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); } }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("role code already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create role", e); }
    }

    public Role update(String code, String name, Boolean enabled) { return updateExtended(code, name, enabled, null, null); }

    public Role updateExtended(String code, String name, Boolean enabled, String dataScope, String deptScope) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (name != null && !name.isBlank()) { fields.add("name = ?"); values.add(name.trim()); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        if (dataScope != null && !dataScope.isBlank()) { fields.add("data_scope = ?"); values.add(dataScope.trim().toUpperCase()); }
        if (deptScope != null) { fields.add("dept_scope = ?"); values.add(deptScope); }
        try (var c = dataSource.getConnection()) {
            if (!fields.isEmpty()) try (var p = c.prepareStatement("UPDATE sys_role SET " + String.join(", ", fields) + " WHERE code = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setString(values.size() + 1, code); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("role not found"); }
            return findByCode(c, code);
        } catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update role", e); }
    }

    public void delete(String code) {
        if ("ADMIN".equalsIgnoreCase(code) || "USER".equalsIgnoreCase(code)) throw new IllegalArgumentException("built-in roles cannot be deleted");
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try { long id = roleId(c, code); bumpPermissionVersion(c, id); try (var p = c.prepareStatement("DELETE FROM sys_role WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("role not found"); } c.commit(); }
            catch (Exception e) { c.rollback(); throw e; }
        }
        catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete role", e); }
    }

    public Role findById(long id) { try (var c = dataSource.getConnection()) { return find(c, id); } catch (java.util.NoSuchElementException e) { throw e; } catch (Exception e) { throw new IllegalStateException("Could not find role", e); } }
    public Role findByCode(String code) { try (var c = dataSource.getConnection()) { return findByCode(c, code); } catch (java.util.NoSuchElementException e) { throw e; } catch (Exception e) { throw new IllegalStateException("Could not find role", e); } }

    public void assignPermissions(String code, List<String> permissions) {
        var uniquePermissions = new LinkedHashSet<>(permissions == null ? List.<String>of() : permissions);
        try (var c = dataSource.getConnection()) { c.setAutoCommit(false); try { long roleId = roleId(c, code); try (var d = c.prepareStatement("DELETE FROM sys_role_permission WHERE role_id = ?")) { d.setLong(1, roleId); d.executeUpdate(); } try (var p = c.prepareStatement("INSERT INTO sys_role_permission(role_id, permission_id) SELECT ?, id FROM sys_permission WHERE code = ?")) { for (String permission : uniquePermissions) { p.setLong(1, roleId); p.setString(2, permission); if (p.executeUpdate() == 0) throw new IllegalArgumentException("unknown permission: " + permission); } } bumpPermissionVersion(c, roleId); c.commit(); } catch (Exception e) { c.rollback(); throw e; } }
        catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not assign role permissions", e); }
    }

    public void assignUsers(String code, List<Long> userIds) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                long roleId = roleId(c, code);
                try (var p = c.prepareStatement("INSERT IGNORE INTO sys_user_role(user_id, role_id) VALUES (?, ?)")) {
                    for (Long userId : userIds == null ? List.<Long>of() : userIds) {
                        if (userId != null) { p.setLong(1, userId); p.setLong(2, roleId); p.addBatch(); }
                    }
                    p.executeBatch();
                }
                bumpPermissionVersion(c, userIds);
                c.commit();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not grant role users", e); }
    }

    public void revokeUsers(String code, List<Long> userIds) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                long roleId = roleId(c, code);
                try (var p = c.prepareStatement("DELETE FROM sys_user_role WHERE role_id = ? AND user_id = ?")) {
                    for (Long userId : userIds == null ? List.<Long>of() : userIds) {
                        if (userId != null) { p.setLong(1, roleId); p.setLong(2, userId); p.addBatch(); }
                    }
                    p.executeBatch();
                }
                bumpPermissionVersion(c, userIds);
                c.commit();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not revoke role users", e); }
    }

    public List<Long> userIds(String code, boolean allocated) {
        String sql = allocated ? "SELECT ur.user_id FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id WHERE r.code = ? ORDER BY ur.user_id" : "SELECT u.id FROM sys_user u WHERE NOT EXISTS (SELECT 1 FROM sys_user_role ur JOIN sys_role r ON r.id = ur.role_id WHERE ur.user_id = u.id AND r.code = ?) ORDER BY u.id";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) { p.setString(1, code); try (var rs = p.executeQuery()) { var result = new ArrayList<Long>(); while (rs.next()) result.add(rs.getLong(1)); return result; } }
        catch (Exception e) { throw new IllegalStateException("Could not list role users", e); }
    }

    private static String select(String suffix) { return "SELECT r.id, r.code, r.name, r.enabled, r.data_scope, r.dept_scope, COALESCE(GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ','), '') permissions FROM sys_role r LEFT JOIN sys_role_permission rp ON rp.role_id = r.id LEFT JOIN sys_permission p ON p.id = rp.permission_id GROUP BY r.id " + suffix; }
    private static long roleId(java.sql.Connection c, String code) throws Exception { try (var p = c.prepareStatement("SELECT id FROM sys_role WHERE code = ?")) { p.setString(1, code); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("role not found"); return rs.getLong(1); } } }
    /** 角色权限或成员变化后递增关联用户的版本。 */
    private static void bumpPermissionVersion(java.sql.Connection c, long roleId) throws Exception { try (var p = c.prepareStatement("UPDATE sys_user u JOIN sys_user_role ur ON ur.user_id = u.id SET u.permission_version = u.permission_version + 1 WHERE ur.role_id = ?")) { p.setLong(1, roleId); p.executeUpdate(); } }
    private static void bumpPermissionVersion(java.sql.Connection c, List<Long> userIds) throws Exception { if (userIds == null) return; try (var p = c.prepareStatement("UPDATE sys_user SET permission_version = permission_version + 1 WHERE id = ?")) { for (Long userId : userIds) { if (userId != null) { p.setLong(1, userId); p.addBatch(); } } p.executeBatch(); } }
    private static Role findByCode(java.sql.Connection c, String code) throws Exception { try (var p = c.prepareStatement(select("HAVING r.code = ?"))) { p.setString(1, code); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("role not found"); return toRole(rs); } } }
    private static Role find(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement(select("HAVING r.id = ?"))) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("role not found"); return toRole(rs); } } }
    private static Role toRole(ResultSet rs) throws Exception { String permissions = rs.getString("permissions"); return new Role(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getBoolean("enabled"), rs.getString("data_scope"), rs.getString("dept_scope"), permissions == null || permissions.isBlank() ? List.of() : List.of(permissions.split(","))); }
    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
}
