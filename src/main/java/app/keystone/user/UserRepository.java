package app.keystone.user;

import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.Connection;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserRepository {
    @Inject DataSource dataSource;

    public Optional<AuthUser> authenticate(String username, String password) {
        String sql = "SELECT id, username, password_hash, display_name FROM sys_user WHERE username = ? AND enabled = true";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setString(1, username);
            long userId;
            try (ResultSet rs = p.executeQuery()) {
                if (!rs.next() || !BcryptUtil.matches(password, rs.getString("password_hash"))) return Optional.empty();
                userId = rs.getLong("id");
            }
            return findAuthUser(c, userId);
        } catch (Exception e) { throw new IllegalStateException("Could not authenticate user", e); }
    }

    public Optional<AuthUser> findAuthUser(long id) {
        try (var c = dataSource.getConnection()) { return findAuthUser(c, id); }
        catch (Exception e) { throw new IllegalStateException("Could not find user", e); }
    }

    public Optional<AuthUser> findAuthUserByUsername(String username) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id FROM sys_user WHERE username = ?")) {
            p.setString(1, username);
            try (var rs = p.executeQuery()) { return rs.next() ? findAuthUser(c, rs.getLong(1)) : Optional.empty(); }
        } catch (Exception e) { throw new IllegalStateException("Could not find user", e); }
    }

    public User findPublic(long id) {
        try (var c = dataSource.getConnection()) { return find(c, id).orElseThrow(); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not find user", e); }
    }

    private Optional<AuthUser> findAuthUser(Connection c, long id) throws Exception {
        try (var p = c.prepareStatement("SELECT id, username, display_name FROM sys_user WHERE id = ? AND enabled = true")) {
            p.setLong(1, id);
            try (var rs = p.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(new AuthUser(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), roles(c, id)));
            }
        }
    }

    public Page list(int page, int size) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size)), offset = (safePage - 1) * safeSize;
        try (var c = dataSource.getConnection(); var count = c.prepareStatement("SELECT COUNT(*) FROM sys_user"); var p = c.prepareStatement("SELECT u.id, u.username, u.display_name, u.dept_id, u.enabled, COALESCE(GROUP_CONCAT(DISTINCT r.code ORDER BY r.code SEPARATOR ','), '') roles FROM sys_user u LEFT JOIN sys_user_role ur ON ur.user_id = u.id LEFT JOIN sys_role r ON r.id = ur.role_id GROUP BY u.id ORDER BY u.id LIMIT ? OFFSET ?")) {
            try (var rs = count.executeQuery()) { rs.next(); long total = rs.getLong(1); p.setInt(1, safeSize); p.setInt(2, offset); try (var rows = p.executeQuery()) { var items = new java.util.ArrayList<User>(); while (rows.next()) items.add(toUser(rows)); return new Page(items, safePage, safeSize, total); } }
        } catch (Exception e) { throw new IllegalStateException("Could not list users", e); }
    }

    public User create(String username, String password, String displayName, Long deptId, List<String> roleCodes) {
        if (username == null || username.isBlank() || password == null || password.isBlank() || displayName == null || displayName.isBlank()) throw new IllegalArgumentException("username, password and displayName are required");
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (var p = c.prepareStatement("INSERT INTO sys_user(username, password_hash, display_name, dept_id) VALUES (?, ?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) {
                p.setString(1, username.trim()); p.setString(2, BcryptUtil.bcryptHash(password)); p.setString(3, displayName.trim()); if (deptId == null) p.setNull(4, java.sql.Types.BIGINT); else p.setLong(4, deptId); p.executeUpdate();
                try (var keys = p.getGeneratedKeys()) { keys.next(); long id = keys.getLong(1); replaceRoles(c, id, roleCodes); c.commit(); return find(c, id).orElseThrow(); }
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("username already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create user", e); }
    }

    public User update(long id, String password, String displayName, Long deptId, Boolean enabled, List<String> roleCodes) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                var fields = new java.util.ArrayList<String>(); var values = new java.util.ArrayList<Object>();
                if (password != null && !password.isBlank()) { fields.add("password_hash = ?"); values.add(BcryptUtil.bcryptHash(password)); }
                if (displayName != null && !displayName.isBlank()) { fields.add("display_name = ?"); values.add(displayName.trim()); }
                if (deptId != null) { fields.add("dept_id = ?"); values.add(deptId); }
                if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
                if (!fields.isEmpty()) { var sql = "UPDATE sys_user SET " + String.join(", ", fields) + " WHERE id = ?"; try (var p = c.prepareStatement(sql)) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("user not found"); } }
                if (roleCodes != null) replaceRoles(c, id, roleCodes);
                c.commit(); return find(c, id).orElseThrow();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update user", e); }
    }

    public void delete(long id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_user WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("user not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete user", e); }
    }

    public void deleteAll(List<Long> ids) {
        if (ids == null || ids.isEmpty()) return;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_user WHERE id = ?")) { for (Long id : ids) { p.setLong(1, id); p.addBatch(); } p.executeBatch(); }
        catch (Exception e) { throw new IllegalStateException("Could not delete users", e); }
    }

    private Optional<User> find(Connection c, long id) throws Exception {
        try (var p = c.prepareStatement("SELECT u.id, u.username, u.display_name, u.dept_id, u.enabled, COALESCE(GROUP_CONCAT(DISTINCT r.code ORDER BY r.code SEPARATOR ','), '') roles FROM sys_user u LEFT JOIN sys_user_role ur ON ur.user_id = u.id LEFT JOIN sys_role r ON r.id = ur.role_id WHERE u.id = ? GROUP BY u.id")) { p.setLong(1, id); try (var rs = p.executeQuery()) { return rs.next() ? Optional.of(toUser(rs)) : Optional.empty(); } }
    }

    private static User toUser(ResultSet rs) throws Exception { long dept = rs.getLong("dept_id"); return new User(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), rs.wasNull() ? null : dept, rs.getBoolean("enabled"), splitRoles(rs.getString("roles"))); }
    private static List<String> roles(Connection c, long userId) throws Exception { try (var p = c.prepareStatement("SELECT r.code FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ? AND r.enabled = true ORDER BY r.code")) { p.setLong(1, userId); try (var rs = p.executeQuery()) { var result = new java.util.ArrayList<String>(); while (rs.next()) result.add(rs.getString(1)); return result; } } }
    private static List<String> splitRoles(String value) { return value == null || value.isBlank() ? List.of("USER") : List.of(value.split(",")); }
    private static void replaceRoles(Connection c, long userId, List<String> roleCodes) throws Exception { var codes = roleCodes == null || roleCodes.isEmpty() ? List.of("USER") : roleCodes.stream().distinct().toList(); try (var d = c.prepareStatement("DELETE FROM sys_user_role WHERE user_id = ?")) { d.setLong(1, userId); d.executeUpdate(); } try (var p = c.prepareStatement("INSERT INTO sys_user_role(user_id, role_id) SELECT ?, id FROM sys_role WHERE code = ? AND enabled = true")) { for (String code : codes) { p.setLong(1, userId); p.setString(2, code); if (p.executeUpdate() == 0) throw new IllegalArgumentException("unknown role: " + code); } } }

    public record AuthUser(long id, String username, String displayName, List<String> roles) {}
    public record Page(java.util.List<User> items, int page, int size, long total) {}
}
