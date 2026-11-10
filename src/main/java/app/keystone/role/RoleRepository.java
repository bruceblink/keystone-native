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

    private static Role toRole(ResultSet rs) throws Exception {
        String permissions = rs.getString("permissions");
        return new Role(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getBoolean("enabled"), permissions == null || permissions.isBlank() ? List.of() : List.of(permissions.split(",")));
    }
}
