package app.keystone.user;

import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.Optional;

@ApplicationScoped
public class UserRepository {
    @Inject DataSource dataSource;

    public Optional<AuthUser> authenticate(String username, String password) {
        String sql = "SELECT id, username, password_hash, display_name FROM sys_user WHERE username = ? AND enabled = true";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setString(1, username);
            try (ResultSet rs = p.executeQuery()) {
                if (!rs.next() || !BcryptUtil.matches(password, rs.getString("password_hash"))) return Optional.empty();
                return Optional.of(new AuthUser(rs.getLong("id"), rs.getString("username"), rs.getString("display_name")));
            }
        } catch (Exception e) { throw new IllegalStateException("Could not authenticate user", e); }
    }

    public Page list(int page, int size) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size)), offset = (safePage - 1) * safeSize;
        try (var c = dataSource.getConnection(); var count = c.prepareStatement("SELECT COUNT(*) FROM sys_user"); var p = c.prepareStatement("SELECT id, username, display_name, enabled FROM sys_user ORDER BY id LIMIT ? OFFSET ?")) {
            try (var rs = count.executeQuery()) { rs.next(); long total = rs.getLong(1); p.setInt(1, safeSize); p.setInt(2, offset); try (var rows = p.executeQuery()) { var items = new java.util.ArrayList<User>(); while (rows.next()) items.add(new User(rows.getLong("id"), rows.getString("username"), rows.getString("display_name"), rows.getBoolean("enabled"))); return new Page(items, safePage, safeSize, total); } }
        } catch (Exception e) { throw new IllegalStateException("Could not list users", e); }
    }

    public record AuthUser(long id, String username, String displayName) {}
    public record Page(java.util.List<User> items, int page, int size, long total) {}
}
