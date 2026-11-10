package app.keystone.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class SystemConfigRepository {
    @Inject DataSource dataSource;

    public List<SystemConfig> list() {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, config_key, config_value, description, enabled, updated_at FROM sys_config ORDER BY config_key"); var rs = p.executeQuery()) { var result = new ArrayList<SystemConfig>(); while (rs.next()) result.add(read(rs)); return result; }
        catch (Exception e) { throw new IllegalStateException("Could not list system configs", e); }
    }

    public SystemConfig find(String key) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, config_key, config_value, description, enabled, updated_at FROM sys_config WHERE config_key = ? AND enabled = true")) { p.setString(1, key); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("config not found"); return read(rs); } }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not find system config", e); }
    }

    public SystemConfig create(String key, String value, String description) {
        require(key, "key"); require(value, "value");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_config(config_key, config_value, description) VALUES (?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, key.trim()); p.setString(2, value); p.setString(3, description); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return byId(c, keys.getLong(1)); } }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("config key already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create system config", e); }
    }

    public SystemConfig update(String key, String value, String description, Boolean enabled) {
        var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
        if (value != null) { fields.add("config_value = ?"); values.add(value); }
        if (description != null) { fields.add("description = ?"); values.add(description); }
        if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
        try (var c = dataSource.getConnection()) { if (!fields.isEmpty()) try (var p = c.prepareStatement("UPDATE sys_config SET " + String.join(", ", fields) + " WHERE config_key = ?")) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setString(values.size() + 1, key); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("config not found"); } return byKey(c, key); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update system config", e); }
    }

    public void delete(String key) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_config WHERE config_key = ?")) { p.setString(1, key); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("config not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete system config", e); }
    }

    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
    private static SystemConfig byKey(java.sql.Connection c, String key) throws Exception { try (var p = c.prepareStatement("SELECT id, config_key, config_value, description, enabled, updated_at FROM sys_config WHERE config_key = ?")) { p.setString(1, key); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("config not found"); return read(rs); } } }
    private static SystemConfig byId(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, config_key, config_value, description, enabled, updated_at FROM sys_config WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("config not found"); return read(rs); } } }
    private static SystemConfig read(ResultSet rs) throws Exception { return new SystemConfig(rs.getLong("id"), rs.getString("config_key"), rs.getString("config_value"), rs.getString("description"), rs.getBoolean("enabled"), rs.getTimestamp("updated_at").toInstant()); }
}
