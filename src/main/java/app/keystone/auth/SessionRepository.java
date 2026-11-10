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
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Duration REFRESH_LIFETIME = Duration.ofDays(14);
    @Inject DataSource dataSource;

    public String create(long userId) {
        String token = randomToken();
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(
                "INSERT INTO sys_refresh_token(user_id, token_hash, expires_at) VALUES (?, ?, ?)")) {
            p.setLong(1, userId);
            p.setString(2, hash(token));
            p.setTimestamp(3, Timestamp.from(Instant.now().plus(REFRESH_LIFETIME)));
            p.executeUpdate();
            return token;
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
                    try (var insert = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, token_hash, expires_at) VALUES (?, ?, ?)")) {
                        insert.setLong(1, userId); insert.setString(2, hash(replacement));
                        insert.setTimestamp(3, Timestamp.from(Instant.now().plus(REFRESH_LIFETIME))); insert.executeUpdate();
                    }
                    c.commit();
                    return users.findAuthUser(userId).map(user -> new RotatedSession(user, replacement));
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

    private static String randomToken() {
        byte[] bytes = new byte[48]; RANDOM.nextBytes(bytes);
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
