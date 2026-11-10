package app.keystone.auth;

import app.keystone.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@ApplicationScoped
public class SessionRepository {
    private static final Duration REFRESH_LIFETIME = Duration.ofDays(14);
    private static final Duration ACCESS_LIFETIME = Duration.ofHours(2);
    @Inject DataSource dataSource;

    public String create(long userId) {
        return create(userId, true).orElseThrow(() -> new IllegalStateException("account already has an active session")).refreshToken();
    }

    public Optional<CreatedSession> create(long userId, boolean forceLogin) {
        String token = randomToken();
        String accessTokenId = java.util.UUID.randomUUID().toString();
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (var cleanup = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL AND (expires_at <= CURRENT_TIMESTAMP OR access_expires_at <= CURRENT_TIMESTAMP)")) { cleanup.setLong(1, userId); cleanup.executeUpdate(); }
                boolean active;
                try (var find = c.prepareStatement("SELECT id FROM sys_refresh_token WHERE user_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND (access_expires_at IS NULL OR access_expires_at > CURRENT_TIMESTAMP) FOR UPDATE")) { find.setLong(1, userId); try (var rs = find.executeQuery()) { active = rs.next(); } }
                if (active && !forceLogin) { c.rollback(); return Optional.empty(); }
                if (active) try (var revoke = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL")) { revoke.setLong(1, userId); revoke.executeUpdate(); }
                try (var p = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, token_hash, expires_at, access_expires_at, access_token_id) VALUES (?, ?, ?, ?, ?)")) {
                    p.setLong(1, userId); p.setString(2, hash(token)); p.setTimestamp(3, Timestamp.from(Instant.now().plus(REFRESH_LIFETIME))); p.setTimestamp(4, Timestamp.from(Instant.now().plus(ACCESS_LIFETIME))); p.setString(5, accessTokenId); p.executeUpdate();
                }
                c.commit(); return Optional.of(new CreatedSession(token, accessTokenId));
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (Exception e) { throw new IllegalStateException("Could not create refresh session", e); }
    }

    public Optional<RotatedSession> rotate(String token, UserRepository users) {
        if (token == null || token.isBlank()) return Optional.empty();
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (var find = c.prepareStatement("SELECT id, user_id FROM sys_refresh_token WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP FOR UPDATE")) {
                find.setString(1, hash(token));
                try (var rs = find.executeQuery()) {
                    if (!rs.next()) { c.rollback(); return Optional.empty(); }
                    long sessionId = rs.getLong("id"), userId = rs.getLong("user_id");
                    try (var revoke = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?")) {
                        revoke.setLong(1, sessionId); revoke.executeUpdate();
                    }
                    String replacement = randomToken(); String accessTokenId = java.util.UUID.randomUUID().toString();
                    try (var insert = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, token_hash, expires_at, access_expires_at, access_token_id) VALUES (?, ?, ?, ?, ?)")) {
                        insert.setLong(1, userId); insert.setString(2, hash(replacement));
                        insert.setTimestamp(3, Timestamp.from(Instant.now().plus(REFRESH_LIFETIME))); insert.setTimestamp(4, Timestamp.from(Instant.now().plus(ACCESS_LIFETIME))); insert.setString(5, accessTokenId); insert.executeUpdate();
                    }
                    var user = users.findAuthUser(c, userId);
                    if (user.isEmpty()) { c.rollback(); return Optional.empty(); }
                    c.commit();
                    return Optional.of(new RotatedSession(user.get(), replacement, accessTokenId));
                }
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (Exception e) { throw new IllegalStateException("Could not rotate refresh session", e); }
    }

    public void revoke(String token) {
        if (token == null || token.isBlank()) return;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND revoked_at IS NULL")) {
            p.setString(1, hash(token)); p.executeUpdate();
        } catch (Exception e) { throw new IllegalStateException("Could not revoke refresh session", e); }
    }

    public void revokeAll(long userId) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL")) { p.setLong(1, userId); p.executeUpdate(); }
        catch (Exception e) { throw new IllegalStateException("Could not revoke user sessions", e); }
    }

    public boolean isAccessTokenActive(String accessTokenId) {
        if (accessTokenId == null || accessTokenId.isBlank()) return true;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT 1 FROM sys_refresh_token WHERE access_token_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND (access_expires_at IS NULL OR access_expires_at > CURRENT_TIMESTAMP)")) { p.setString(1, accessTokenId); try (var rs = p.executeQuery()) { return rs.next(); } }
        catch (Exception e) { throw new IllegalStateException("Could not validate access session", e); }
    }

    public java.util.List<OnlineSession> activeSessions(String username, String ipAddress) {
        StringBuilder sql = new StringBuilder("SELECT s.id, s.user_id, u.username, u.display_name, u.login_ip, s.created_at, s.expires_at, s.access_expires_at FROM sys_refresh_token s JOIN sys_user u ON u.id = s.user_id WHERE s.revoked_at IS NULL AND s.expires_at > CURRENT_TIMESTAMP AND (s.access_expires_at IS NULL OR s.access_expires_at > CURRENT_TIMESTAMP)");
        if (username != null && !username.isBlank()) sql.append(" AND u.username LIKE ?");
        if (ipAddress != null && !ipAddress.isBlank()) sql.append(" AND u.login_ip LIKE ?");
        sql.append(" ORDER BY s.created_at DESC");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql.toString())) {
            int index = 1; if (username != null && !username.isBlank()) p.setString(index++, "%" + username.trim() + "%"); if (ipAddress != null && !ipAddress.isBlank()) p.setString(index, "%" + ipAddress.trim() + "%");
            var result = new java.util.ArrayList<OnlineSession>(); try (var rs = p.executeQuery()) { while (rs.next()) { var created = rs.getTimestamp("created_at"); var expires = rs.getTimestamp("expires_at"); var access = rs.getTimestamp("access_expires_at"); result.add(new OnlineSession(rs.getLong("id"), rs.getLong("user_id"), rs.getString("username"), rs.getString("display_name"), rs.getString("login_ip"), created == null ? null : created.toInstant(), expires == null ? null : expires.toInstant(), access == null ? null : access.toInstant())); } } return result;
        } catch (Exception e) { throw new IllegalStateException("Could not list online sessions", e); }
    }

    public void revokeById(long sessionId) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL")) { p.setLong(1, sessionId); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("session not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not revoke session", e); }
    }

    private static String randomToken() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); }
    }

    public record CreatedSession(String refreshToken, String accessTokenId) {}
    public record RotatedSession(UserRepository.AuthUser user, String refreshToken, String accessTokenId) {}
    public record OnlineSession(long sessionId, long userId, String username, String displayName, String ipAddress, java.time.Instant createdAt, java.time.Instant expiresAt, java.time.Instant accessExpiresAt) {}
}
