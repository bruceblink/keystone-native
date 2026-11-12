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
    public static final String DEFAULT_CLIENT_ID = "web";
    private static final Duration REFRESH_LIFETIME = Duration.ofDays(14);
    private static final Duration ACCESS_LIFETIME = Duration.ofMinutes(5);
    private static final Duration IDLE_LIFETIME = Duration.ofHours(24);
    @Inject DataSource dataSource;

    public String create(long userId) {
        return create(userId, true).orElseThrow(() -> new IllegalStateException("account already has an active session")).refreshToken();
    }

    public Optional<CreatedSession> create(long userId, boolean forceLogin) {
        return create(userId, forceLogin, DEFAULT_CLIENT_ID);
    }

    /** 创建绑定客户端的刷新会话；客户端标识会贯穿令牌族的每次轮换。 */
    public Optional<CreatedSession> create(long userId, boolean forceLogin, String clientId) {
        String boundClientId = normalizeClientId(clientId);
        String token = randomToken();
        String accessTokenId = java.util.UUID.randomUUID().toString();
        String sessionId = java.util.UUID.randomUUID().toString();
        String familyId = java.util.UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant refreshExpiry = now.plus(REFRESH_LIFETIME);
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (var cleanup = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL AND (expires_at <= CURRENT_TIMESTAMP OR access_expires_at <= CURRENT_TIMESTAMP OR idle_expires_at <= CURRENT_TIMESTAMP)")) { cleanup.setLong(1, userId); cleanup.executeUpdate(); }
                boolean active;
                try (var find = c.prepareStatement("SELECT id FROM sys_refresh_token WHERE user_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND access_expires_at > CURRENT_TIMESTAMP AND idle_expires_at > CURRENT_TIMESTAMP FOR UPDATE")) { find.setLong(1, userId); try (var rs = find.executeQuery()) { active = rs.next(); } }
                if (active && !forceLogin) { c.rollback(); return Optional.empty(); }
                if (active) try (var revoke = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL")) { revoke.setLong(1, userId); revoke.executeUpdate(); }
                try (var p = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, session_id, refresh_family_id, client_id, token_hash, expires_at, idle_expires_at, access_expires_at, access_token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                    p.setLong(1, userId); p.setString(2, sessionId); p.setString(3, familyId); p.setString(4, boundClientId); p.setString(5, hash(token)); p.setTimestamp(6, Timestamp.from(refreshExpiry)); p.setTimestamp(7, Timestamp.from(now.plus(IDLE_LIFETIME))); p.setTimestamp(8, Timestamp.from(now.plus(ACCESS_LIFETIME))); p.setString(9, accessTokenId); p.executeUpdate();
                }
                recordEvent(c, null, userId, familyId, "ISSUED", boundClientId, null);
                c.commit(); return Optional.of(new CreatedSession(token, accessTokenId, sessionId, refreshExpiry, boundClientId));
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (Exception e) { throw new IllegalStateException("Could not create refresh session", e); }
    }

    public Optional<RotatedSession> rotate(String token, UserRepository users) {
        return rotate(token, users, DEFAULT_CLIENT_ID);
    }

    /** 只允许原客户端刷新；客户端不匹配时撤销整个令牌族并记录安全事件。 */
    public Optional<RotatedSession> rotate(String token, UserRepository users, String clientId) {
        if (token == null || token.isBlank()) return Optional.empty();
        String requestedClientId = normalizeClientId(clientId);
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (var find = c.prepareStatement("SELECT id, user_id, session_id, refresh_family_id, client_id, expires_at, idle_expires_at, revoked_at FROM sys_refresh_token WHERE token_hash = ? FOR UPDATE")) {
                find.setString(1, hash(token));
                try (var rs = find.executeQuery()) {
                    if (!rs.next()) { c.rollback(); return Optional.empty(); }
                    long tokenId = rs.getLong("id"), userId = rs.getLong("user_id");
                    String sessionId = rs.getString("session_id"), familyId = rs.getString("refresh_family_id"), boundClientId = rs.getString("client_id");
                    Timestamp refreshExpiry = rs.getTimestamp("expires_at"), idleExpiry = rs.getTimestamp("idle_expires_at");
                    if (boundClientId == null || !boundClientId.equals(requestedClientId)) {
                        if (familyId != null) try (var revoke = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE refresh_family_id = ?")) { revoke.setString(1, familyId); revoke.executeUpdate(); }
                        recordEvent(c, tokenId, userId, familyId, "CLIENT_MISMATCH", requestedClientId, "refresh client does not match session client");
                        c.commit(); return Optional.empty();
                    }
                    boolean invalid = rs.getTimestamp("revoked_at") != null || refreshExpiry == null || !refreshExpiry.toInstant().isAfter(Instant.now()) || (idleExpiry != null && !idleExpiry.toInstant().isAfter(Instant.now()));
                    if (invalid) {
                        if (familyId != null) try (var reuse = c.prepareStatement("UPDATE sys_refresh_token SET reused_at = COALESCE(reused_at, CURRENT_TIMESTAMP), revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE refresh_family_id = ?")) { reuse.setString(1, familyId); reuse.executeUpdate(); }
                        recordEvent(c, tokenId, userId, familyId, "REUSE_DETECTED", requestedClientId, "refresh token was already revoked or expired");
                        c.commit(); return Optional.empty();
                    }
                    try (var revoke = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL")) { revoke.setLong(1, tokenId); revoke.executeUpdate(); }
                    String replacement = randomToken(), accessTokenId = java.util.UUID.randomUUID().toString();
                    Instant nextIdle = Instant.now().plus(IDLE_LIFETIME); if (nextIdle.isAfter(refreshExpiry.toInstant())) nextIdle = refreshExpiry.toInstant();
                    try (var insert = c.prepareStatement("INSERT INTO sys_refresh_token(user_id, session_id, refresh_family_id, client_id, token_hash, expires_at, idle_expires_at, access_expires_at, access_token_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                        insert.setLong(1, userId); insert.setString(2, sessionId); insert.setString(3, familyId); insert.setString(4, boundClientId); insert.setString(5, hash(replacement)); insert.setTimestamp(6, refreshExpiry); insert.setTimestamp(7, Timestamp.from(nextIdle)); insert.setTimestamp(8, Timestamp.from(Instant.now().plus(ACCESS_LIFETIME))); insert.setString(9, accessTokenId); insert.executeUpdate();
                    }
                    recordEvent(c, tokenId, userId, familyId, "ROTATED", boundClientId, null);
                    var user = users.findAuthUser(c, userId);
                    if (user.isEmpty()) { c.rollback(); return Optional.empty(); }
                    c.commit(); return Optional.of(new RotatedSession(user.get(), replacement, accessTokenId, sessionId, refreshExpiry.toInstant(), boundClientId));
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

    public void revokeSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE session_id = ? AND revoked_at IS NULL")) { p.setString(1, sessionId); p.executeUpdate(); }
        catch (Exception e) { throw new IllegalStateException("Could not revoke session", e); }
    }

    public boolean isAccessTokenActive(String accessTokenId) {
        // 访问令牌必须携带非空 jti；缺少会话标识时按无效令牌处理。
        if (accessTokenId == null || accessTokenId.isBlank()) return false;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT 1 FROM sys_refresh_token WHERE access_token_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP AND access_expires_at > CURRENT_TIMESTAMP AND idle_expires_at > CURRENT_TIMESTAMP")) { p.setString(1, accessTokenId); try (var rs = p.executeQuery()) { return rs.next(); } }
        catch (Exception e) { throw new IllegalStateException("Could not validate access session", e); }
    }

    /** 同时核验主体权限版本，角色变更后立即撤销旧访问令牌。 */
    public boolean isAccessTokenActive(String accessTokenId, long userId, long permissionVersion) {
        if (accessTokenId == null || accessTokenId.isBlank() || userId <= 0 || permissionVersion < 0) return false;
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT 1 FROM sys_refresh_token t JOIN sys_user u ON u.id = t.user_id WHERE t.access_token_id = ? AND t.user_id = ? AND u.permission_version = ? AND t.revoked_at IS NULL AND t.expires_at > CURRENT_TIMESTAMP AND t.access_expires_at > CURRENT_TIMESTAMP AND t.idle_expires_at > CURRENT_TIMESTAMP")) {
            p.setString(1, accessTokenId); p.setLong(2, userId); p.setLong(3, permissionVersion);
            try (var rs = p.executeQuery()) { return rs.next(); }
        } catch (Exception e) { throw new IllegalStateException("Could not validate access permission version", e); }
    }

    public java.util.List<OnlineSession> activeSessions(String username, String ipAddress) {
        StringBuilder sql = new StringBuilder("SELECT s.id, s.user_id, u.username, u.display_name, u.login_ip, s.created_at, s.expires_at, s.access_expires_at FROM sys_refresh_token s JOIN sys_user u ON u.id = s.user_id WHERE s.revoked_at IS NULL AND s.expires_at > CURRENT_TIMESTAMP AND s.access_expires_at > CURRENT_TIMESTAMP AND s.idle_expires_at > CURRENT_TIMESTAMP");
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

    /** 只接受稳定的短标识，避免把未校验的请求字段写入会话和审计记录。 */
    private static String normalizeClientId(String value) {
        String normalized = value == null || value.isBlank() ? DEFAULT_CLIENT_ID : value.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) throw new IllegalArgumentException("invalid clientId");
        return normalized;
    }

    private static String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); }
    }

    private static void recordEvent(java.sql.Connection c, Long tokenId, long userId, String familyId, String eventType, String clientId, String detail) throws Exception {
        try (var p = c.prepareStatement("INSERT INTO sys_refresh_token_event(token_id, user_id, refresh_family_id, event_type, client_id, detail) VALUES (?, ?, ?, ?, ?, ?)")) { if (tokenId == null) p.setNull(1, java.sql.Types.BIGINT); else p.setLong(1, tokenId); p.setLong(2, userId); p.setString(3, familyId); p.setString(4, eventType); p.setString(5, clientId); p.setString(6, detail); p.executeUpdate(); }
    }

    public record CreatedSession(String refreshToken, String accessTokenId, String sessionId, Instant refreshExpiresAt, String clientId) {}
    public record RotatedSession(UserRepository.AuthUser user, String refreshToken, String accessTokenId, String sessionId, Instant refreshExpiresAt, String clientId) {}
    public record OnlineSession(long sessionId, long userId, String username, String displayName, String ipAddress, java.time.Instant createdAt, java.time.Instant expiresAt, java.time.Instant accessExpiresAt) {}
}
