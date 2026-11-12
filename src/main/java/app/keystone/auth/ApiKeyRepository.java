package app.keystone.auth;

import app.keystone.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@ApplicationScoped
public class ApiKeyRepository {
    private static final SecureRandom RANDOM = new SecureRandom();
    @Inject DataSource dataSource;

    public IssuedApiKey issue(long userId, String name, List<String> scopes, Instant expiresAt) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("name is required");
        if (name.trim().length() > 128) throw new IllegalArgumentException("name is too long");
        if (expiresAt != null && (expiresAt.isBefore(Instant.now()) || expiresAt.isAfter(Instant.now().plusSeconds(90L * 24 * 3600)))) throw new IllegalArgumentException("expiresAt must be within 90 days");
        List<String> normalizedScopes = normalizeScopes(scopes);
        if (normalizedScopes.isEmpty()) throw new IllegalArgumentException("at least one scope is required");
        Set<String> allowed = permissions(userId);
        if (!allowed.containsAll(normalizedScopes)) throw new IllegalArgumentException("scope exceeds issuer permissions");
        String secret = random(32);
        String prefix = random(8);
        String value = "ks_live_" + prefix + "_" + secret;
        String id = UUID.randomUUID().toString();
        String scopeText = String.join(" ", normalizedScopes);
        String subjectId = ensureSubject(userId);
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_api_key(id, user_id, subject_id, created_by, name, key_prefix, key_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            p.setString(1, id); p.setLong(2, userId); p.setString(3, subjectId); p.setLong(4, userId); p.setString(5, name.trim()); p.setString(6, prefix); p.setString(7, hash(value)); p.setString(8, scopeText); if (expiresAt == null) p.setTimestamp(9, null); else p.setTimestamp(9, Timestamp.from(expiresAt)); p.executeUpdate();
            return new IssuedApiKey(id, name.trim(), prefix, value, normalizedScopes, expiresAt);
        } catch (Exception e) { throw new IllegalStateException("Could not issue API key", e); }
    }

    public Principal authenticate(String value) {
        if (value == null || value.isBlank()) return null;
        String sql = "SELECT k.id, k.subject_id, k.user_id, k.scopes, u.username FROM sys_api_key k JOIN sys_user u ON u.id = k.user_id JOIN sys_service_subject s ON s.id = k.subject_id WHERE k.key_hash = ? AND u.enabled = true AND s.enabled = true AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > CURRENT_TIMESTAMP)";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setString(1, hash(value));
            try (var rs = p.executeQuery()) {
                if (!rs.next()) return null;
                String id = rs.getString("id"); String scopes = rs.getString("scopes");
                try (var touch = c.prepareStatement("UPDATE sys_api_key SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?")) { touch.setString(1, id); touch.executeUpdate(); }
                return new Principal(id, rs.getString("subject_id"), rs.getLong("user_id"), rs.getString("username"), scopes == null || scopes.isBlank() ? List.of() : List.of(scopes.split(" ")));
            }
        } catch (Exception e) { throw new IllegalStateException("Could not authenticate API key", e); }
    }

    public void revoke(long userId, String id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_api_key SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP), revoked_reason = COALESCE(revoked_reason, 'revoked by owner') WHERE id = ? AND user_id = ?")) { p.setString(1, id); p.setLong(2, userId); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("API key not found"); }
        catch (java.util.NoSuchElementException e) { throw e; } catch (Exception e) { throw new IllegalStateException("Could not revoke API key", e); }
    }

    public List<ApiKeyMetadata> list(long userId) {
        String sql = "SELECT id, name, key_prefix, scopes, expires_at, revoked_at, last_used_at, created_at FROM sys_api_key WHERE user_id = ? ORDER BY created_at DESC";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) { p.setLong(1, userId); try (var rs = p.executeQuery()) { var result = new ArrayList<ApiKeyMetadata>(); while (rs.next()) result.add(new ApiKeyMetadata(rs.getString("id"), rs.getString("name"), rs.getString("key_prefix"), split(rs.getString("scopes")), instant(rs, "expires_at"), instant(rs, "revoked_at"), instant(rs, "last_used_at"), instant(rs, "created_at"))); return result; } }
        catch (Exception e) { throw new IllegalStateException("Could not list API keys", e); }
    }

    public IssuedApiKey rotate(long userId, String id) {
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try (var find = c.prepareStatement("SELECT subject_id, name, scopes, expires_at, revoked_at FROM sys_api_key WHERE id = ? AND user_id = ? FOR UPDATE")) {
                find.setString(1, id); find.setLong(2, userId);
                try (var rs = find.executeQuery()) {
                    if (!rs.next()) throw new java.util.NoSuchElementException("API key not found");
                    if (rs.getTimestamp("revoked_at") != null) throw new IllegalArgumentException("API key is already revoked");
                    String subjectId = rs.getString("subject_id"); String name = rs.getString("name"); List<String> scopes = split(rs.getString("scopes")); var expires = instant(rs, "expires_at");
                    String secret = random(32); String prefix = random(8); String value = "ks_live_" + prefix + "_" + secret; String replacementId = UUID.randomUUID().toString();
                    try (var insert = c.prepareStatement("INSERT INTO sys_api_key(id, user_id, subject_id, created_by, name, key_prefix, key_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) { insert.setString(1, replacementId); insert.setLong(2, userId); insert.setString(3, subjectId); insert.setLong(4, userId); insert.setString(5, name); insert.setString(6, prefix); insert.setString(7, hash(value)); insert.setString(8, String.join(" ", scopes)); if (expires == null) insert.setTimestamp(9, null); else insert.setTimestamp(9, Timestamp.from(expires)); insert.executeUpdate(); }
                    try (var revoke = c.prepareStatement("UPDATE sys_api_key SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'rotated', rotated_to = ? WHERE id = ?")) { revoke.setString(1, replacementId); revoke.setString(2, id); revoke.executeUpdate(); }
                    c.commit(); return new IssuedApiKey(replacementId, name, prefix, value, scopes, expires);
                }
            } catch (Exception e) { c.rollback(); throw e; }
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not rotate API key", e); }
    }

    private String ensureSubject(long userId) {
        String code = "user:" + userId;
        try (var c = dataSource.getConnection()) {
            try (var p = c.prepareStatement("INSERT INTO sys_service_subject(id, code, name, owner_user_id) SELECT ?, ?, CONCAT('User API keys: ', ?), ? WHERE NOT EXISTS (SELECT 1 FROM sys_service_subject WHERE code = ?)") ) { p.setString(1, UUID.randomUUID().toString()); p.setString(2, code); p.setLong(3, userId); p.setLong(4, userId); p.setString(5, code); p.executeUpdate(); }
            try (var p = c.prepareStatement("SELECT id FROM sys_service_subject WHERE code = ?")) { p.setString(1, code); try (var rs = p.executeQuery()) { if (!rs.next()) throw new IllegalStateException("service subject not found"); return rs.getString(1); } }
        } catch (Exception e) { throw new IllegalStateException("Could not create service subject", e); }
    }

    private Set<String> permissions(long userId) {
        String sql = "SELECT DISTINCT p.code FROM sys_permission p JOIN sys_role_permission rp ON rp.permission_id = p.id JOIN sys_user_role ur ON ur.role_id = rp.role_id JOIN sys_role r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.enabled = true";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) { p.setLong(1, userId); try (var rs = p.executeQuery()) { Set<String> result = new HashSet<>(); while (rs.next()) result.add(rs.getString(1)); return result; } }
        catch (Exception e) { throw new IllegalStateException("Could not resolve API key permissions", e); }
    }

    private static List<String> normalizeScopes(Collection<String> scopes) {
        if (scopes == null) return List.of();
        return scopes.stream().filter(s -> s != null && !s.isBlank()).map(String::trim).map(String::toLowerCase).distinct().sorted().peek(s -> { if (!s.matches("[a-z0-9][a-z0-9._-]*:[a-z0-9][a-z0-9._-]*")) throw new IllegalArgumentException("invalid scope: " + s); }).toList();
    }
    private static List<String> split(String value) { return value == null || value.isBlank() ? List.of() : List.of(value.split(" ")); }
    private static Instant instant(java.sql.ResultSet rs, String column) throws Exception { var value = rs.getTimestamp(column); return value == null ? null : value.toInstant(); }

    private static String random(int bytes) { byte[] value = new byte[bytes]; RANDOM.nextBytes(value); return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static String hash(String value) { try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); } }
    public record IssuedApiKey(String id, String name, String prefix, String apiKey, List<String> scopes, Instant expiresAt) {}
    public record Principal(String keyId, String subjectId, long userId, String username, List<String> scopes) {}
    public record ApiKeyMetadata(String id, String name, String prefix, List<String> scopes, Instant expiresAt, Instant revokedAt, Instant lastUsedAt, Instant createdAt) {}
}
