package app.keystone.notice;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class NoticeRepository {
    @Inject DataSource dataSource;

    public List<Notice> list(boolean publicOnly) {
        String sql = "SELECT id, title, content, notice_type, published, enabled, publish_at, created_by, created_at FROM sys_notice " + (publicOnly ? "WHERE published = true AND enabled = true AND (publish_at IS NULL OR publish_at <= CURRENT_TIMESTAMP) " : "") + "ORDER BY COALESCE(publish_at, created_at) DESC, id DESC";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql); var rs = p.executeQuery()) { var result = new ArrayList<Notice>(); while (rs.next()) result.add(read(rs)); return result; }
        catch (Exception e) { throw new IllegalStateException("Could not list notices", e); }
    }

    public Notice create(String title, String content, String type, String createdBy) {
        require(title, "title"); require(content, "content");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_notice(title, content, notice_type, created_by) VALUES (?, ?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, title.trim()); p.setString(2, content); p.setString(3, type == null ? "NOTICE" : type); p.setString(4, createdBy); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); } }
        catch (Exception e) { throw new IllegalStateException("Could not create notice", e); }
    }

    public Notice update(long id, String title, String content, String type, Boolean enabled) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (title != null && !title.isBlank()) { fields.add("title = ?"); values.add(title.trim()); }
        if (content != null) { fields.add("content = ?"); values.add(content); }
        if (type != null) { fields.add("notice_type = ?"); values.add(type); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        try (var c = dataSource.getConnection()) { if (!fields.isEmpty()) try (var p = c.prepareStatement("UPDATE sys_notice SET " + String.join(", ", fields) + " WHERE id = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("notice not found"); } return find(c, id); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update notice", e); }
    }

    public Notice publish(long id, boolean published) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_notice SET published = ?, publish_at = ? WHERE id = ?")) { p.setBoolean(1, published); if (published) p.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now())); else p.setNull(2, java.sql.Types.TIMESTAMP); p.setLong(3, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("notice not found"); return find(c, id); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not publish notice", e); }
    }

    public void delete(long id) { try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_notice WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("notice not found"); } catch (java.util.NoSuchElementException e) { throw e; } catch (Exception e) { throw new IllegalStateException("Could not delete notice", e); } }
    private static void require(String v, String f) { if (v == null || v.isBlank()) throw new IllegalArgumentException(f + " is required"); }
    private static Notice find(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, title, content, notice_type, published, enabled, publish_at, created_by, created_at FROM sys_notice WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("notice not found"); return read(rs); } } }
    private static Notice read(ResultSet rs) throws Exception { var publish = rs.getTimestamp("publish_at"); return new Notice(rs.getLong("id"), rs.getString("title"), rs.getString("content"), rs.getString("notice_type"), rs.getBoolean("published"), rs.getBoolean("enabled"), publish == null ? null : publish.toInstant(), rs.getString("created_by"), rs.getTimestamp("created_at").toInstant()); }
}
