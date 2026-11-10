package app.keystone.menu;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class MenuRepository {
    @Inject DataSource dataSource;

    public List<Menu> listForRoles(List<String> roles) {
        String sql;
        if (roles.contains("ADMIN")) sql = baseSql() + " ORDER BY COALESCE(m.parent_id, 0), m.sort_order, m.id";
        else if (roles.isEmpty()) return List.of();
        else sql = "SELECT m.id, m.parent_id, m.code, m.name, m.path, m.component, m.menu_type, m.permission, m.sort_order, m.enabled FROM sys_menu m JOIN sys_role_menu rm ON rm.menu_id = m.id JOIN sys_role r ON r.id = rm.role_id WHERE m.enabled = true AND r.code IN (" + "? ,".repeat(roles.size()).replaceAll(",$", "") + ") GROUP BY m.id ORDER BY COALESCE(m.parent_id, 0), m.sort_order, m.id";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            if (!roles.contains("ADMIN")) for (int i = 0; i < roles.size(); i++) p.setString(i + 1, roles.get(i));
            try (var rs = p.executeQuery()) { var result = new ArrayList<Menu>(); while (rs.next()) result.add(read(rs)); return result; }
        } catch (Exception e) { throw new IllegalStateException("Could not list menus", e); }
    }

    public Menu create(MenuRequest request) {
        require(request.code(), "code"); require(request.name(), "name");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_menu(parent_id, code, name, path, component, menu_type, permission, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) {
            setLong(p, 1, request.parentId()); p.setString(2, request.code().trim()); p.setString(3, request.name().trim()); p.setString(4, request.path()); p.setString(5, request.component()); p.setString(6, request.menuType() == null ? "MENU" : request.menuType()); p.setString(7, request.permission()); p.setInt(8, request.sortOrder() == null ? 0 : request.sortOrder()); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); }
        } catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("menu code already exists or parent does not exist", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create menu", e); }
    }

    public Menu update(long id, MenuRequest request) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (request.name() != null && !request.name().isBlank()) { fields.add("name = ?"); values.add(request.name().trim()); }
        if (request.path() != null) { fields.add("path = ?"); values.add(request.path()); }
        if (request.component() != null) { fields.add("component = ?"); values.add(request.component()); }
        if (request.menuType() != null) { fields.add("menu_type = ?"); values.add(request.menuType()); }
        if (request.permission() != null) { fields.add("permission = ?"); values.add(request.permission()); }
        if (request.sortOrder() != null) { fields.add("sort_order = ?"); values.add(request.sortOrder()); }
        if (request.enabled() != null) { fields.add("enabled = ?"); values.add(request.enabled()); }
        try (var c = dataSource.getConnection()) {
            if (!fields.isEmpty()) try (var p = c.prepareStatement("UPDATE sys_menu SET " + String.join(", ", fields) + " WHERE id = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("menu not found"); }
            return find(c, id);
        } catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update menu", e); }
    }

    public void delete(long id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_menu WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("menu not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("menu has child menus", e); }
        catch (Exception e) { throw new IllegalStateException("Could not delete menu", e); }
    }

    public void assignRoles(long menuId, List<String> roleCodes) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (var d = c.prepareStatement("DELETE FROM sys_role_menu WHERE menu_id = ?")) { d.setLong(1, menuId); d.executeUpdate(); }
                try (var p = c.prepareStatement("INSERT INTO sys_role_menu(role_id, menu_id) SELECT id, ? FROM sys_role WHERE code = ?")) { for (String code : roleCodes == null ? List.<String>of() : roleCodes) { p.setLong(1, menuId); p.setString(2, code); if (p.executeUpdate() == 0) throw new IllegalArgumentException("unknown role: " + code); } }
                c.commit();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (Exception e) { if (e instanceof IllegalArgumentException) throw (IllegalArgumentException) e; throw new IllegalStateException("Could not assign menu roles", e); }
    }

    private static String baseSql() { return "SELECT m.id, m.parent_id, m.code, m.name, m.path, m.component, m.menu_type, m.permission, m.sort_order, m.enabled FROM sys_menu m WHERE m.enabled = true"; }
    private static Menu find(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, parent_id, code, name, path, component, menu_type, permission, sort_order, enabled FROM sys_menu WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("menu not found"); return read(rs); } } }
    private static Menu read(ResultSet rs) throws Exception { long parent = rs.getLong("parent_id"); return new Menu(rs.getLong("id"), rs.wasNull() ? null : parent, rs.getString("code"), rs.getString("name"), rs.getString("path"), rs.getString("component"), rs.getString("menu_type"), rs.getString("permission"), rs.getInt("sort_order"), rs.getBoolean("enabled")); }
    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
    private static void setLong(java.sql.PreparedStatement p, int index, Long value) throws Exception { if (value == null) p.setNull(index, java.sql.Types.BIGINT); else p.setLong(index, value); }
    public record MenuRequest(Long parentId, String code, String name, String path, String component, String menuType, String permission, Integer sortOrder, Boolean enabled) {}
}
