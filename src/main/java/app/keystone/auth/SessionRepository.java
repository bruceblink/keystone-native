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
        return create(userId, true).orElseThrow(() -> new IllegalStateException("account already has an active session"));
    }

    public Optional<String> create(long userId, boolean forceLogin) {
        String token = randomToken();
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (var cleanup = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL AND (expires_at <= CURRENT_TIMESTAMP OR access_expires_at <= CURRENT_TIMESTAMP)")) { cleanup.setLong(1, userId); cleanup.executeUpdate(); }
                boolean active;
                try (var find = c.prepareStatement("SELECT id FROM sys_refresh_token WHERE user_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND (access_expires_at IS NULL OR access_expires_at > CURRENT_TIMESTAMP) FOR UPDATE")) { find.setLong(1, userId); try (var rs = find.executeQuery()) { active = rs.next(); } }
                if (active && !forceLogin) { c.rollback(); return Optional.empty(); }
                if (active) try (var revoke = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL")) { revoke.setLong(1, userId); revoke.executeUpdate(); }
                try (var p = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, token_hash, expires_at, access_expires_at) VALUES (?, ?, ?, ?)")) {
                    p.setLong(1, userId); p.setString(2, hash(token)); p.setTimestamp(3, Timestamp.from(Instant.now().plus(REFRESH_LIFETIME))); p.setTimestamp(4, Timestamp.from(Instant.now().plus(ACCESS_LIFETIME))); p.executeUpdate();
                }
                c.commit(); return Optional.of(token);
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
                    String replacement = randomToken();
                    try (var insert = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, token_hash, expires_at, access_expires_at) VALUES (?, ?, ?, ?)")) {
                        insert.setLong(1, userId); insert.setString(2, hash(replacement));
                        insert.setTimestamp(3, Timestamp.from(Instant.now().plus(REFRESH_LIFETIME))); insert.setTimestamp(4, Timestamp.from(Instant.now().plus(ACCESS_LIFETIME))); insert.executeUpdate();
                    }
                    var user = users.findAuthUser(c, userId);
                    if (user.isEmpty()) { c.rollback(); return Optional.empty(); }
                    c.commit();
                    return Optional.of(new RotatedSession(user.get(), replacement));
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

    public record RotatedSession(UserRepository.AuthUser user, String refreshToken) {}
}
