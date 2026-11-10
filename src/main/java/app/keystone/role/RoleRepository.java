package app.keystone.role;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class RoleRepository {
    @Inject DataSource dataSource;

    public List<Role> list() {
        String sql = "SELECT r.id, r.code, r.name, r.enabled, COALESCE(GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ','), '') permissions FROM sys_role r LEFT JOIN sys_role_permission rp ON rp.role_id = r.id LEFT JOIN sys_permission p ON p.id = rp.permission_id GROUP BY r.id ORDER BY r.code";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql); var rs = p.executeQuery()) {
            var roles = new ArrayList<Role>(); while (rs.next()) roles.add(toRole(rs)); return roles;
        } catch (Exception e) { throw new IllegalStateException("Could not list roles", e); }
    }

    public Role create(String code, String name) {
        require(code, "code"); require(name, "name");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_role(code, name) VALUES (?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, code.trim()); p.setString(2, name.trim()); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); } }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("role code already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create role", e); }
    }

    public Role update(String code, String name, Boolean enabled) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (name != null && !name.isBlank()) { fields.add("name = ?"); values.add(name.trim()); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        try (var c = dataSource.getConnection()) { if (!fields.isEmpty()) try (var p = c.prepareStatement("UPDATE sys_role SET " + String.join(", ", fields) + " WHERE code = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setString(values.size() + 1, code); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("role not found"); } return findByCode(c, code); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update role", e); }
    }

    public void delete(String code) {
        if ("ADMIN".equalsIgnoreCase(code) || "USER".equalsIgnoreCase(code)) throw new IllegalArgumentException("built-in roles cannot be deleted");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_role WHERE code = ?")) { p.setString(1, code); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("role not found"); }
        catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete role", e); }
    }

    public void assignPermissions(String code, List<String> permissions) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                long roleId = roleId(c, code);
                try (var d = c.prepareStatement("DELETE FROM sys_role_permission WHERE role_id = ?")) { d.setLong(1, roleId); d.executeUpdate(); }
                try (var p = c.prepareStatement("INSERT INTO sys_role_permission(role_id, permission_id) SELECT ?, id FROM sys_permission WHERE code = ?")) { for (String permission : permissions == null ? List.<String>of() : permissions) { p.setLong(1, roleId); p.setString(2, permission); if (p.executeUpdate() == 0) throw new IllegalArgumentException("unknown permission: " + permission); } }
                c.commit();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not assign role permissions", e); }
    }

    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
    private static long roleId(java.sql.Connection c, String code) throws Exception { try (var p = c.prepareStatement("SELECT id FROM sys_role WHERE code = ?")) { p.setString(1, code); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("role not found"); return rs.getLong(1); } } }
    private static Role findByCode(java.sql.Connection c, String code) throws Exception { try (var p = c.prepareStatement("SELECT r.id, r.code, r.name, r.enabled, COALESCE(GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ','), '') permissions FROM sys_role r LEFT JOIN sys_role_permission rp ON rp.role_id = r.id LEFT JOIN sys_permission p ON p.id = rp.permission_id WHERE r.code = ? GROUP BY r.id")) { p.setString(1, code); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("role not found"); return toRole(rs); } } }
    private static Role find(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT r.id, r.code, r.name, r.enabled, COALESCE(GROUP_CONCAT(DISTINCT p.code ORDER BY p.code SEPARATOR ','), '') permissions FROM sys_role r LEFT JOIN sys_role_permission rp ON rp.role_id = r.id LEFT JOIN sys_permission p ON p.id = rp.permission_id WHERE r.id = ? GROUP BY r.id")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("role not found"); return toRole(rs); } } }

    private static Role toRole(ResultSet rs) throws Exception {
        String permissions = rs.getString("permissions");
        return new Role(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getBoolean("enabled"), permissions == null || permissions.isBlank() ? List.of() : List.of(permissions.split(",")));
    }
}
