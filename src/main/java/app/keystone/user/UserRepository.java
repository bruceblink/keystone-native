package app.keystone.user;

import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserRepository {
    @Inject DataSource dataSource;

    public Optional<AuthUser> authenticate(String username, String password) {
        String sql = "SELECT id, password_hash FROM sys_user WHERE username = ? AND enabled = true";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setString(1, username);
            long userId;
            try (ResultSet rs = p.executeQuery()) {
                if (!rs.next() || password == null || !BcryptUtil.matches(password, rs.getString("password_hash"))) return Optional.empty();
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
            p.setString(1, username); long userId;
            try (var rs = p.executeQuery()) { if (!rs.next()) return Optional.empty(); userId = rs.getLong(1); }
            return findAuthUser(c, userId);
        } catch (Exception e) { throw new IllegalStateException("Could not find user", e); }
    }

    public User findPublic(long id) {
        try (var c = dataSource.getConnection()) { return find(c, id).orElseThrow(); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not find user", e); }
    }

    public Optional<AuthUser> findAuthUser(Connection c, long id) throws Exception {
        String sql = "SELECT id, username, display_name, must_change_password, dept_id, post_id, email, phone_number, sex, avatar, login_ip, login_at, remark FROM sys_user WHERE id = ? AND enabled = true";
        try (var p = c.prepareStatement(sql)) {
            p.setLong(1, id);
            try (var rs = p.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                Long dept = nullableLong(rs, "dept_id"); Long post = nullableLong(rs, "post_id");
                var loginAt = rs.getTimestamp("login_at");
                return Optional.of(new AuthUser(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), roles(c, id), rs.getBoolean("must_change_password"), dept, post, rs.getString("email"), rs.getString("phone_number"), nullableInt(rs, "sex"), rs.getString("avatar"), rs.getString("login_ip"), loginAt == null ? null : loginAt.toInstant(), rs.getString("remark")));
            }
        }
    }

    public Page list(int page, int size) { return list(page, size, null, null, null, null); }

    public Page list(int page, int size, String username, String displayName, Long deptId, Boolean enabled) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size));
        long offset = (long) (safePage - 1) * safeSize;
        String filters = filters(username, displayName, deptId, enabled);
        String countSql = "SELECT COUNT(*) FROM sys_user u" + filters;
        String listSql = "SELECT u.id, u.username, u.display_name, u.dept_id, u.post_id, u.enabled, u.email, u.phone_number, u.sex, u.avatar, u.login_ip, u.login_at, u.remark, COALESCE(GROUP_CONCAT(DISTINCT r.code ORDER BY r.code SEPARATOR ','), '') roles FROM sys_user u LEFT JOIN sys_user_role ur ON ur.user_id = u.id LEFT JOIN sys_role r ON r.id = ur.role_id" + filters + " GROUP BY u.id ORDER BY u.id LIMIT ? OFFSET ?";
        try (var c = dataSource.getConnection(); var count = c.prepareStatement(countSql); var p = c.prepareStatement(listSql)) {
            int index = bindFilters(count, 1, username, displayName, deptId, enabled);
            bindFilters(p, 1, username, displayName, deptId, enabled);
            long total;
            try (var rs = count.executeQuery()) { rs.next(); total = rs.getLong(1); }
            p.setInt(index, safeSize); p.setLong(index + 1, offset);
            var items = new ArrayList<User>();
            try (var rows = p.executeQuery()) { while (rows.next()) items.add(toUser(rows)); }
            return new Page(items, safePage, safeSize, total);
        } catch (Exception e) { throw new IllegalStateException("Could not list users", e); }
    }

    public User create(String username, String password, String displayName, Long deptId, List<String> roleCodes) {
        return create(username, password, displayName, deptId, null, null, null, null, null, null, roleCodes);
    }

    public User create(String username, String password, String displayName, Long deptId, Long postId, String email, String phoneNumber, Integer sex, String avatar, String remark, List<String> roleCodes) {
        if (username == null || username.isBlank() || password == null || password.isBlank() || displayName == null || displayName.isBlank()) throw new IllegalArgumentException("username, password and displayName are required");
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (var p = c.prepareStatement("INSERT INTO sys_user(username, password_hash, display_name, dept_id, post_id, email, phone_number, sex, avatar, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) {
                p.setString(1, username.trim()); p.setString(2, BcryptUtil.bcryptHash(password)); p.setString(3, displayName.trim()); setLong(p, 4, deptId); setLong(p, 5, postId); p.setString(6, email); p.setString(7, phoneNumber); setInt(p, 8, sex); p.setString(9, avatar); p.setString(10, remark); p.executeUpdate();
                try (var keys = p.getGeneratedKeys()) { keys.next(); long id = keys.getLong(1); replaceRoles(c, id, roleCodes); c.commit(); return find(c, id).orElseThrow(); }
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("username already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create user", e); }
    }

    public User update(long id, String password, String displayName, Long deptId, Boolean enabled, List<String> roleCodes) {
        return updateExtended(id, password, displayName, deptId != null, deptId, null, null, null, null, null, null, enabled, roleCodes);
    }

    public User updateExtended(long id, String password, String displayName, boolean updateDept, Long deptId, Long postId, String email, String phoneNumber, Integer sex, String avatar, String remark, Boolean enabled, List<String> roleCodes) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                var fields = new ArrayList<String>(); var values = new ArrayList<Object>();
                if (password != null && !password.isBlank()) { fields.add("password_hash = ?"); values.add(BcryptUtil.bcryptHash(password)); fields.add("must_change_password = false"); }
                if (displayName != null && !displayName.isBlank()) { fields.add("display_name = ?"); values.add(displayName.trim()); }
                if (updateDept) { fields.add("dept_id = ?"); values.add(deptId); }
                if (postId != null) { fields.add("post_id = ?"); values.add(postId); }
                if (email != null) { fields.add("email = ?"); values.add(emptyToNull(email)); }
                if (phoneNumber != null) { fields.add("phone_number = ?"); values.add(emptyToNull(phoneNumber)); }
                if (sex != null) { fields.add("sex = ?"); values.add(sex); }
                if (avatar != null) { fields.add("avatar = ?"); values.add(emptyToNull(avatar)); }
                if (remark != null) { fields.add("remark = ?"); values.add(emptyToNull(remark)); }
                if (enabled != null) { fields.add("enabled = ?"); values.add(enabled); }
                if (!fields.isEmpty()) {
                    var sql = "UPDATE sys_user SET " + String.join(", ", fields) + " WHERE id = ?";
                    try (var p = c.prepareStatement(sql)) { for (int i = 0; i < values.size(); i++) p.setObject(i + 1, values.get(i)); p.setLong(values.size() + 1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("user not found"); }
                }
                if (roleCodes != null) replaceRoles(c, id, roleCodes);
                c.commit(); return find(c, id).orElseThrow();
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not update user", e); }
    }

    public void markLogin(long id, String ip) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_user SET login_ip = ?, login_at = CURRENT_TIMESTAMP WHERE id = ?")) { p.setString(1, ip); p.setLong(2, id); p.executeUpdate(); }
        catch (Exception e) { throw new IllegalStateException("Could not update login metadata", e); }
    }

    public void delete(long id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_user WHERE id = ? AND username <> 'admin'")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("user not found or protected"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete user", e); }
    }

    public int deleteAll(List<Long> ids) {
        if (ids == null || ids.isEmpty()) return 0;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_user WHERE id = ? AND username <> 'admin'")) {
            for (Long id : ids) { if (id != null) { p.setLong(1, id); p.addBatch(); } } int[] result = p.executeBatch(); int count = 0; for (int value : result) if (value > 0) count += value; return count;
        } catch (Exception e) { throw new IllegalStateException("Could not delete users", e); }
    }

    private Optional<User> find(Connection c, long id) throws Exception {
        String sql = "SELECT u.id, u.username, u.display_name, u.dept_id, u.post_id, u.enabled, u.email, u.phone_number, u.sex, u.avatar, u.login_ip, u.login_at, u.remark, COALESCE(GROUP_CONCAT(DISTINCT r.code ORDER BY r.code SEPARATOR ','), '') roles FROM sys_user u LEFT JOIN sys_user_role ur ON ur.user_id = u.id LEFT JOIN sys_role r ON r.id = ur.role_id WHERE u.id = ? GROUP BY u.id";
        try (var p = c.prepareStatement(sql)) { p.setLong(1, id); try (var rs = p.executeQuery()) { return rs.next() ? Optional.of(toUser(rs)) : Optional.empty(); } }
    }

    private static User toUser(ResultSet rs) throws Exception {
        var loginAt = rs.getTimestamp("login_at");
        return new User(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), nullableLong(rs, "dept_id"), nullableLong(rs, "post_id"), rs.getBoolean("enabled"), rs.getString("email"), rs.getString("phone_number"), nullableInt(rs, "sex"), rs.getString("avatar"), rs.getString("login_ip"), loginAt == null ? null : loginAt.toInstant(), rs.getString("remark"), splitRoles(rs.getString("roles")));
    }

    private static List<String> roles(Connection c, long userId) throws Exception { try (var p = c.prepareStatement("SELECT r.code FROM sys_role r JOIN sys_user_role ur ON ur.role_id = r.id WHERE ur.user_id = ? AND r.enabled = true ORDER BY r.code")) { p.setLong(1, userId); try (var rs = p.executeQuery()) { var result = new ArrayList<String>(); while (rs.next()) result.add(rs.getString(1)); return result; } } }
    public List<String> permissions(long userId) {
        String sql = "SELECT DISTINCT p.code FROM sys_permission p JOIN sys_role_permission rp ON rp.permission_id = p.id JOIN sys_user_role ur ON ur.role_id = rp.role_id JOIN sys_role r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.enabled = true ORDER BY p.code";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) { p.setLong(1, userId); try (var rs = p.executeQuery()) { var result = new ArrayList<String>(); while (rs.next()) result.add(rs.getString(1)); return result; } }
        catch (Exception e) { throw new IllegalStateException("Could not list user permissions", e); }
    }
    private static List<String> splitRoles(String value) { return value == null || value.isBlank() ? List.of("USER") : List.of(value.split(",")); }
    private static void replaceRoles(Connection c, long userId, List<String> roleCodes) throws Exception { var codes = roleCodes == null || roleCodes.isEmpty() ? List.of("USER") : roleCodes.stream().filter(java.util.Objects::nonNull).map(String::trim).filter(s -> !s.isBlank()).distinct().toList(); try (var d = c.prepareStatement("DELETE FROM sys_user_role WHERE user_id = ?")) { d.setLong(1, userId); d.executeUpdate(); } try (var p = c.prepareStatement("INSERT INTO sys_user_role(user_id, role_id) SELECT ?, id FROM sys_role WHERE code = ? AND enabled = true")) { for (String code : codes) { p.setLong(1, userId); p.setString(2, code); if (p.executeUpdate() == 0) throw new IllegalArgumentException("unknown role: " + code); } } }

    private static String filters(String username, String displayName, Long deptId, Boolean enabled) { var parts = new ArrayList<String>(); if (username != null && !username.isBlank()) parts.add("u.username LIKE ?"); if (displayName != null && !displayName.isBlank()) parts.add("u.display_name LIKE ?"); if (deptId != null) parts.add("u.dept_id = ?"); if (enabled != null) parts.add("u.enabled = ?"); return parts.isEmpty() ? "" : " WHERE " + String.join(" AND ", parts); }
    private static int bindFilters(java.sql.PreparedStatement p, int index, String username, String displayName, Long deptId, Boolean enabled) throws Exception { if (username != null && !username.isBlank()) p.setString(index++, "%" + username.trim() + "%"); if (displayName != null && !displayName.isBlank()) p.setString(index++, "%" + displayName.trim() + "%"); if (deptId != null) p.setLong(index++, deptId); if (enabled != null) p.setBoolean(index++, enabled); return index; }
    private static Long nullableLong(ResultSet rs, String column) throws Exception { long value = rs.getLong(column); return rs.wasNull() ? null : value; }
    private static Integer nullableInt(ResultSet rs, String column) throws Exception { int value = rs.getInt(column); return rs.wasNull() ? null : value; }
    private static void setLong(java.sql.PreparedStatement p, int index, Long value) throws Exception { if (value == null) p.setNull(index, java.sql.Types.BIGINT); else p.setLong(index, value); }
    private static void setInt(java.sql.PreparedStatement p, int index, Integer value) throws Exception { if (value == null) p.setNull(index, java.sql.Types.TINYINT); else p.setInt(index, value); }
    private static String emptyToNull(String value) { return value == null || value.isBlank() ? null : value.trim(); }

    public record AuthUser(long id, String username, String displayName, List<String> roles, boolean mustChangePassword,
                           Long deptId, Long postId, String email, String phoneNumber, Integer sex, String avatar,
                           String loginIp, java.time.Instant loginAt, String remark) {}
    public record Page(List<User> items, int page, int size, long total) {}
}
