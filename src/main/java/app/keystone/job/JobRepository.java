package app.keystone.job;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class JobRepository {
    @Inject DataSource dataSource;

    public List<Job> list() {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, code, name, cron, enabled, last_status, last_run_at FROM sys_job ORDER BY id"); var rs = p.executeQuery()) { var result = new ArrayList<Job>(); while (rs.next()) result.add(read(rs)); return result; }
        catch (Exception e) { throw new IllegalStateException("Could not list jobs", e); }
    }

    public List<Job> enabled() {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, code, name, cron, enabled, last_status, last_run_at FROM sys_job WHERE enabled = true ORDER BY id"); var rs = p.executeQuery()) { var result = new ArrayList<Job>(); while (rs.next()) result.add(read(rs)); return result; }
        catch (Exception e) { throw new IllegalStateException("Could not load enabled jobs", e); }
    }

    public Job create(String code, String name, String cron) {
        require(code, "code"); require(name, "name"); require(cron, "cron");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_job(code, name, cron) VALUES (?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, code.trim()); p.setString(2, name.trim()); p.setString(3, cron.trim()); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return find(c, keys.getLong(1)); } }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("job code already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create job", e); }
    }

    public Job update(long id, String name, String cron, Boolean enabled) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (name != null && !name.isBlank()) { fields.add("name = ?"); values.add(name.trim()); }
        if (cron != null && !cron.isBlank()) { fields.add("cron = ?"); values.add(cron.trim()); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        try (var c = dataSource.getConnection()) {
            if (!fields.isEmpty()) { try (var p = c.prepareStatement("UPDATE sys_job SET " + String.join(", ", fields) + " WHERE id = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("job not found"); } }
            return find(c, id);
        } catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update job", e); }
    }

    public void markRun(long id, String status) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_job SET last_status = ?, last_run_at = CURRENT_TIMESTAMP WHERE id = ?")) { p.setString(1, status); p.setLong(2, id); p.executeUpdate(); }
        catch (Exception ignored) { }
    }

    public void delete(long id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_job WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("job not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete job", e); }
    }

    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
    private static Job find(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, code, name, cron, enabled, last_status, last_run_at FROM sys_job WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("job not found"); return read(rs); } } }
    private static Job read(ResultSet rs) throws Exception { var timestamp = rs.getTimestamp("last_run_at"); return new Job(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getString("cron"), rs.getBoolean("enabled"), rs.getString("last_status"), timestamp == null ? null : timestamp.toInstant()); }
}
