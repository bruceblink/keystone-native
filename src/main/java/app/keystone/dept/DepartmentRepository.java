package app.keystone.dept;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class DepartmentRepository {
    @Inject DataSource dataSource;

    public List<Department> list() {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, parent_id, code, name, sort_order, enabled FROM sys_dept ORDER BY COALESCE(parent_id, 0), sort_order, id"); var rs = p.executeQuery()) {
            var result = new ArrayList<Department>(); while (rs.next()) result.add(read(rs)); return result;
        } catch (Exception e) { throw new IllegalStateException("Could not list departments", e); }
    }

    public Department create(String code, String name, Long parentId, Integer sortOrder) {
        if (code == null || code.isBlank() || name == null || name.isBlank()) throw new IllegalArgumentException("code and name are required");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_dept(parent_id, code, name, sort_order) VALUES (?, ?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) {
            setParent(p, 1, parentId); p.setString(2, code.trim()); p.setString(3, name.trim()); p.setInt(4, sortOrder == null ? 0 : sortOrder); p.executeUpdate();
            try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); }
        } catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("department code already exists or parent does not exist", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create department", e); }
    }

    public Department update(long id, String name, Long parentId, Integer sortOrder, Boolean enabled) {
        if (parentId != null && parentId == id) throw new IllegalArgumentException("department cannot be its own parent");
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (name != null && !name.isBlank()) { fields.add("name = ?"); values.add(name.trim()); }
        if (parentId != null) { fields.add("parent_id = ?"); values.add(parentId); }
        if (sortOrder != null) { fields.add("sort_order = ?"); values.add(sortOrder); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        try (var c = dataSource.getConnection()) {
            if (!fields.isEmpty()) { try (var p = c.prepareStatement("UPDATE sys_dept SET " + String.join(", ", fields) + " WHERE id = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("department not found"); } }
            return find(c, id);
        } catch (java.util.NoSuchElementException e) { throw e; }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("parent department does not exist", e); }
        catch (Exception e) { throw new IllegalStateException("Could not update department", e); }
    }

    public void delete(long id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_dept WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("department not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("department has child departments", e); }
        catch (Exception e) { throw new IllegalStateException("Could not delete department", e); }
    }

    private static Department read(java.sql.ResultSet rs) throws Exception { long parent = rs.getLong("parent_id"); return new Department(rs.getLong("id"), rs.wasNull() ? null : parent, rs.getString("code"), rs.getString("name"), rs.getInt("sort_order"), rs.getBoolean("enabled")); }
    private static Department find(Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, parent_id, code, name, sort_order, enabled FROM sys_dept WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("department not found"); return read(rs); } } }
    private static void setParent(java.sql.PreparedStatement p, int index, Long parentId) throws Exception { if (parentId == null) p.setNull(index, java.sql.Types.BIGINT); else p.setLong(index, parentId); }
}
