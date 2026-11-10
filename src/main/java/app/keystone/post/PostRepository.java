package app.keystone.post;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class PostRepository {
    @Inject DataSource dataSource;

    public List<Post> list() {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, code, name, sort_order, enabled FROM sys_post ORDER BY sort_order, id"); var rs = p.executeQuery()) { var result = new ArrayList<Post>(); while (rs.next()) result.add(read(rs)); return result; }
        catch (Exception e) { throw new IllegalStateException("Could not list posts", e); }
    }

    public Post create(String code, String name, Integer sortOrder) {
        require(code, "code"); require(name, "name");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_post(code, name, sort_order) VALUES (?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, code.trim()); p.setString(2, name.trim()); p.setInt(3, sortOrder == null ? 0 : sortOrder); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); } }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("post code already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create post", e); }
    }

    public Post update(long id, String name, Integer sortOrder, Boolean enabled) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (name != null && !name.isBlank()) { fields.add("name = ?"); values.add(name.trim()); }
        if (sortOrder != null) { fields.add("sort_order = ?"); values.add(sortOrder); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        try (var c = dataSource.getConnection()) { if (!fields.isEmpty()) try (var p = c.prepareStatement("UPDATE sys_post SET " + String.join(", ", fields) + " WHERE id = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("post not found"); } return find(c, id); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update post", e); }
    }

    public void delete(long id) { try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_post WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("post not found"); } catch (java.util.NoSuchElementException e) { throw e; } catch (Exception e) { throw new IllegalStateException("Could not delete post", e); } }
    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
    private static Post find(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, code, name, sort_order, enabled FROM sys_post WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("post not found"); return read(rs); } } }
    private static Post read(ResultSet rs) throws Exception { return new Post(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getInt("sort_order"), rs.getBoolean("enabled")); }
}
