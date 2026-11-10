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

    public Page list(int page, int size) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size)), offset = (safePage - 1) * safeSize;
        String countSql = "SELECT COUNT(*) FROM sys_operation_log";
        String listSql = "SELECT id, actor_username, action, resource, resource_id, detail, created_at FROM sys_operation_log ORDER BY id DESC LIMIT ? OFFSET ?";
        try (var c = dataSource.getConnection(); var count = c.prepareStatement(countSql); var p = c.prepareStatement(listSql)) {
            try (var rs = count.executeQuery()) { rs.next(); long total = rs.getLong(1); p.setInt(1, safeSize); p.setInt(2, offset); try (var rows = p.executeQuery()) { var items = new ArrayList<OperationLog>(); while (rows.next()) items.add(new OperationLog(rows.getLong("id"), rows.getString("actor_username"), rows.getString("action"), rows.getString("resource"), rows.getString("resource_id"), rows.getString("detail"), rows.getTimestamp("created_at").toInstant())); return new Page(items, safePage, safeSize, total); } }
        } catch (Exception e) { throw new IllegalStateException("Could not list operation logs", e); }
    }

    public record Page(java.util.List<OperationLog> items, int page, int size, long total) {}
}
