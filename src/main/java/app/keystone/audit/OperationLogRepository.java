package app.keystone.audit;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.Timestamp;
import java.util.ArrayList;

@ApplicationScoped
public class OperationLogRepository {
    @Inject DataSource dataSource;

    public void record(String actor, String action, String resource, String resourceId, String detail) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_operation_log(actor_username, action, resource, resource_id, detail) VALUES (?, ?, ?, ?, ?)")) {
            p.setString(1, actor == null || actor.isBlank() ? "system" : actor); p.setString(2, action); p.setString(3, resource); p.setString(4, resourceId); p.setString(5, detail); p.executeUpdate();
        } catch (Exception ignored) { /* Audit logging must not break the business operation. */ }
    }

    public Page list(int page, int size) { return list(page, size, null, null, null); }

    public Page list(int page, int size, String actor, String action, String resource) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size)); long offset = (long) (safePage - 1) * safeSize;
        String filter = filter(actor, action, resource);
        String countSql = "SELECT COUNT(*) FROM sys_operation_log" + filter;
        String listSql = "SELECT id, actor_username, action, resource, resource_id, detail, created_at FROM sys_operation_log" + filter + " ORDER BY id DESC LIMIT ? OFFSET ?";
        try (var c = dataSource.getConnection(); var count = c.prepareStatement(countSql); var p = c.prepareStatement(listSql)) {
            int index = bind(count, 1, actor, action, resource); bind(p, 1, actor, action, resource);
            try (var rs = count.executeQuery()) { rs.next(); long total = rs.getLong(1); p.setInt(index, safeSize); p.setLong(index + 1, offset); try (var rows = p.executeQuery()) { var items = new ArrayList<OperationLog>(); while (rows.next()) items.add(new OperationLog(rows.getLong("id"), rows.getString("actor_username"), rows.getString("action"), rows.getString("resource"), rows.getString("resource_id"), rows.getString("detail"), rows.getTimestamp("created_at").toInstant())); return new Page(items, safePage, safeSize, total); } }
        } catch (Exception e) { throw new IllegalStateException("Could not list operation logs", e); }
    }

    public int delete(java.util.List<Long> ids) {
        if (ids == null || ids.isEmpty()) return 0;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_operation_log WHERE id = ?")) { for (Long id : ids) { p.setLong(1, id); p.addBatch(); } int total = 0; for (int value : p.executeBatch()) if (value > 0) total += value; return total; }
        catch (Exception e) { throw new IllegalStateException("Could not delete operation logs", e); }
    }

    private static String filter(String actor, String action, String resource) { var parts = new ArrayList<String>(); if (actor != null && !actor.isBlank()) parts.add("actor_username LIKE ?"); if (action != null && !action.isBlank()) parts.add("action = ?"); if (resource != null && !resource.isBlank()) parts.add("resource = ?"); return parts.isEmpty() ? "" : " WHERE " + String.join(" AND ", parts); }
    private static int bind(java.sql.PreparedStatement p, int index, String actor, String action, String resource) throws Exception { if (actor != null && !actor.isBlank()) p.setString(index++, "%" + actor.trim() + "%"); if (action != null && !action.isBlank()) p.setString(index++, action.trim()); if (resource != null && !resource.isBlank()) p.setString(index++, resource.trim()); return index; }

    public record Page(java.util.List<OperationLog> items, int page, int size, long total) {}
}
