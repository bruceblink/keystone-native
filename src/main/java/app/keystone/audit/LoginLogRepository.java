package app.keystone.audit;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.util.ArrayList;

@ApplicationScoped
public class LoginLogRepository {
    @Inject DataSource dataSource;

    public void record(String username, String status, String ipAddress, String message, String userAgent) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_login_log(username, status, ip_address, message, user_agent) VALUES (?, ?, ?, ?, ?)")) {
            p.setString(1, username == null || username.isBlank() ? "unknown" : username); p.setString(2, status); p.setString(3, ipAddress); p.setString(4, message); p.setString(5, userAgent); p.executeUpdate();
        } catch (Exception ignored) { }
    }

    public Page list(int page, int size, String username, String status) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size)); long offset = (long) (safePage - 1) * safeSize;
        String filter = filter(username, status);
        try (var c = dataSource.getConnection(); var count = c.prepareStatement("SELECT COUNT(*) FROM sys_login_log" + filter); var p = c.prepareStatement("SELECT id, username, status, ip_address, message, user_agent, login_at FROM sys_login_log" + filter + " ORDER BY id DESC LIMIT ? OFFSET ?")) {
            int index = bind(count, 1, username, status); bind(p, 1, username, status); long total;
            try (var rs = count.executeQuery()) { rs.next(); total = rs.getLong(1); }
            p.setInt(index, safeSize); p.setLong(index + 1, offset); var items = new ArrayList<LoginLog>();
            try (var rs = p.executeQuery()) { while (rs.next()) items.add(read(rs)); }
            return new Page(items, safePage, safeSize, total);
        } catch (Exception e) { throw new IllegalStateException("Could not list login logs", e); }
    }

    public int delete(java.util.List<Long> ids) {
        if (ids == null || ids.isEmpty()) return 0;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_login_log WHERE id = ?")) { for (Long id : ids) { p.setLong(1, id); p.addBatch(); } int total = 0; for (int value : p.executeBatch()) if (value > 0) total += value; return total; }
        catch (Exception e) { throw new IllegalStateException("Could not delete login logs", e); }
    }

    private static String filter(String username, String status) { var parts = new ArrayList<String>(); if (username != null && !username.isBlank()) parts.add("username LIKE ?"); if (status != null && !status.isBlank()) parts.add("status = ?"); return parts.isEmpty() ? "" : " WHERE " + String.join(" AND ", parts); }
    private static int bind(java.sql.PreparedStatement p, int index, String username, String status) throws Exception { if (username != null && !username.isBlank()) p.setString(index++, "%" + username.trim() + "%"); if (status != null && !status.isBlank()) p.setString(index++, status.trim()); return index; }
    private static LoginLog read(java.sql.ResultSet rs) throws Exception { var timestamp = rs.getTimestamp("login_at"); return new LoginLog(rs.getLong("id"), rs.getString("username"), rs.getString("status"), rs.getString("ip_address"), rs.getString("message"), rs.getString("user_agent"), timestamp == null ? null : timestamp.toInstant()); }
    public record Page(java.util.List<LoginLog> items, int page, int size, long total) {}
}
