package app.keystone.auth;

import app.keystone.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/** 使用 ORM 管理会话、刷新令牌和令牌事件；所有状态变化在一个数据库事务内完成。 */
@ApplicationScoped
public class SessionRepository {
    public static final String DEFAULT_CLIENT_ID = "web";
    private static final Duration REFRESH_LIFETIME = Duration.ofDays(14);
    private static final Duration ACCESS_LIFETIME = Duration.ofMinutes(5);
    private static final Duration IDLE_LIFETIME = Duration.ofHours(24);

    @Inject AuthSessionRepository sessions;
    @Inject RefreshTokenRepository tokens;
    @Inject RefreshTokenEventRepository events;
    @Inject ApiKeyUserRepository users;

    @Transactional
    public String create(String userId) {
        return createSession(userId, true, DEFAULT_CLIENT_ID)
                .orElseThrow(() -> new IllegalStateException("account already has an active session"))
                .refreshToken();
    }

    @Transactional
    public Optional<CreatedSession> create(String userId, boolean forceLogin) {
        return createSession(userId, forceLogin, DEFAULT_CLIENT_ID);
    }

    /** 创建绑定客户端的刷新会话；锁定用户行以串行化同一账户的并发登录。 */
    @Transactional
    public Optional<CreatedSession> create(String userId, boolean forceLogin, String clientId) {
        return createSession(userId, forceLogin, clientId);
    }

    private Optional<CreatedSession> createSession(String userId, boolean forceLogin, String clientId) {
        String boundClientId = normalizeClientId(clientId);
        ApiKeyUserEntity user = users.findForUpdate(userId);
        if (user == null) throw new IllegalStateException("user is unavailable");

        Instant now = Instant.now();
        Instant refreshExpiry = now.plus(REFRESH_LIFETIME);
        revokeExpiredTokens(userId, now);
        List<AuthSessionEntity> active = sessions.findActiveForUser(userId, now);
        if (!active.isEmpty() && !forceLogin) return Optional.empty();
        if (!active.isEmpty()) {
            for (AuthSessionEntity session : active) {
                session.revoke(now);
                revokeFamily(session.refreshFamilyId(), now);
            }
        }

        String token = randomToken();
        String accessTokenId = UUID.randomUUID().toString();
        String sessionId = UUID.randomUUID().toString();
        String familyId = UUID.randomUUID().toString();
        String approvedScope = String.join(" ", users.permissions(user));
        AuthSessionEntity session = new AuthSessionEntity(sessionId, userId, boundClientId, approvedScope,
                familyId, refreshExpiry, now.plus(IDLE_LIFETIME), now);
        RefreshTokenEntity refresh = new RefreshTokenEntity(userId, sessionId, familyId, boundClientId,
                hash(token), refreshExpiry, now.plus(IDLE_LIFETIME), now.plus(ACCESS_LIFETIME), accessTokenId);
        sessions.persist(session);
        tokens.persist(refresh);
        events.record(null, userId, familyId, "ISSUED", boundClientId, null);
        return Optional.of(new CreatedSession(token, accessTokenId, sessionId, refreshExpiry, boundClientId, approvedScope));
    }

    @Transactional
    public Optional<RotatedSession> rotate(String token, UserRepository ignoredUsers) {
        return rotate(token, ignoredUsers, DEFAULT_CLIENT_ID);
    }

    /** 只允许原客户端刷新；锁顺序固定为刷新令牌后会话，避免并发轮换形成反向等待。 */
    @Transactional
    public Optional<RotatedSession> rotate(String token, UserRepository ignoredUsers, String clientId) {
        if (token == null || token.isBlank()) return Optional.empty();
        String requestedClientId = normalizeClientId(clientId);
        Instant now = Instant.now();
        RefreshTokenEntity current = tokens.findForUpdateByHash(hash(token));
        if (current == null) return Optional.empty();
        AuthSessionEntity session = current.sessionId() == null ? null : sessions.findForUpdate(current.sessionId());
        if (session == null) return Optional.empty();

        if (current.clientId() == null || !current.clientId().equals(requestedClientId)) {
            session.revoke(now);
            revokeFamily(current.refreshFamilyId(), now);
            events.record(current.id(), current.userId(), current.refreshFamilyId(), "CLIENT_MISMATCH",
                    requestedClientId, "refresh client does not match session client");
            return Optional.empty();
        }

        if (!current.activeAt(now) || !session.activeAt(now)) {
            session.revoke(now);
            markFamilyReused(current.refreshFamilyId(), now);
            events.record(current.id(), current.userId(), current.refreshFamilyId(), "REUSE_DETECTED",
                    requestedClientId, "refresh token was already revoked or expired");
            return Optional.empty();
        }

        ApiKeyUserEntity user = users.findEnabledEntity(current.userId());
        if (user == null) return Optional.empty();

        current.revoke(now);
        String replacement = randomToken();
        String accessTokenId = UUID.randomUUID().toString();
        Instant nextIdle = now.plus(IDLE_LIFETIME);
        if (nextIdle.isAfter(current.expiresAt())) nextIdle = current.expiresAt();
        tokens.persist(new RefreshTokenEntity(current.userId(), current.sessionId(), current.refreshFamilyId(),
                current.clientId(), hash(replacement), current.expiresAt(), nextIdle,
                now.plus(ACCESS_LIFETIME), accessTokenId));
        session.touch(now, nextIdle);
        events.record(current.id(), current.userId(), current.refreshFamilyId(), "ROTATED", current.clientId(), null);
        return Optional.of(new RotatedSession(user.toAuthUser(), replacement, accessTokenId, session.id(),
                current.expiresAt(), current.clientId(), session.approvedScope()));
    }

    @Transactional
    public void revoke(String token) {
        if (token == null || token.isBlank()) return;
        Instant now = Instant.now();
        RefreshTokenEntity current = tokens.findForUpdateByHash(hash(token));
        if (current == null) return;
        AuthSessionEntity session = current.sessionId() == null ? null : sessions.findForUpdate(current.sessionId());
        if (session != null) session.revoke(now);
        current.revoke(now);
    }

    @Transactional
    public void revokeAll(String userId) {
        Instant now = Instant.now();
        ApiKeyUserEntity user = users.findForUpdate(userId);
        if (user == null) return;
        for (AuthSessionEntity session : sessions.findByUser(userId)) session.revoke(now);
        for (RefreshTokenEntity token : tokens.findByUser(userId)) token.revoke(now);
    }

    @Transactional
    public void revokeSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return;
        Instant now = Instant.now();
        AuthSessionEntity session = sessions.findForUpdate(sessionId);
        if (session == null) return;
        session.revoke(now);
        for (RefreshTokenEntity token : tokens.find("sessionId", sessionId).list()) token.revoke(now);
    }

    public boolean isAccessTokenActive(String accessTokenId) {
        if (accessTokenId == null || accessTokenId.isBlank()) return false;
        Instant now = Instant.now();
        RefreshTokenEntity token = tokens.findByAccessToken(accessTokenId, now);
        if (token == null || token.sessionId() == null) return false;
        AuthSessionEntity session = sessions.findById(token.sessionId());
        return session != null && session.activeAt(now);
    }

    /** 同时核验主体权限版本，角色变更后立即撤销旧访问令牌。 */
    public boolean isAccessTokenActive(String accessTokenId, String userId, long permissionVersion) {
        if (accessTokenId == null || accessTokenId.isBlank() || userId == null || permissionVersion < 0) return false;
        Instant now = Instant.now();
        RefreshTokenEntity token = tokens.findByAccessTokenAndVersion(accessTokenId, userId, now);
        if (token == null || token.sessionId() == null) return false;
        ApiKeyUserEntity user = users.findEnabledEntity(userId);
        AuthSessionEntity session = sessions.findById(token.sessionId());
        return user != null && session != null && session.activeAt(now) && user.permissionVersion() == permissionVersion;
    }

    /** 返回仍有效的令牌记录；sessionId 保持旧接口的 long 令牌 ID 语义。 */
    public List<OnlineSession> activeSessions(String username, String ipAddress) {
        Instant now = Instant.now();
        List<OnlineSession> result = new ArrayList<>();
        for (AuthSessionEntity session : sessions.findAll().list()) {
            if (!session.activeAt(now)) continue;
            ApiKeyUserEntity user = users.findEnabledEntity(session.userId());
            if (user == null) continue;
            if (username != null && !username.isBlank() && !user.username().contains(username.trim())) continue;
            if (ipAddress != null && !ipAddress.isBlank() && (user.loginIp() == null || !user.loginIp().contains(ipAddress.trim()))) continue;
            RefreshTokenEntity token = tokens.find("sessionId = ?1 and revokedAt is null", session.id()).firstResult();
            if (token == null || token.id() == null) continue;
            result.add(new OnlineSession(token.id(), user.id(), user.username(), user.displayName(), user.loginIp(),
                    session.createdAt(), session.refreshExpiresAt(), token.accessExpiresAt()));
        }
        return result;
    }

    @Transactional
    public void revokeById(String sessionId) {
        RefreshTokenEntity token = tokens.findById(app.keystone.identity.UuidValues.parse(sessionId));
        if (token == null) throw new java.util.NoSuchElementException("session not found");
        Instant now = Instant.now();
        AuthSessionEntity session = token.sessionId() == null ? null : sessions.findForUpdate(token.sessionId());
        if (session != null) session.revoke(now);
        if (token.sessionId() == null) {
            token.revoke(now);
            return;
        }
        for (RefreshTokenEntity familyToken : tokens.find("sessionId", token.sessionId()).list()) familyToken.revoke(now);
    }

    private void revokeExpiredTokens(String userId, Instant now) {
        for (RefreshTokenEntity token : tokens.findByUser(userId)) {
            if (!token.activeAt(now)) token.revoke(now);
        }
    }

    private void revokeFamily(String familyId, Instant now) {
        if (familyId == null) return;
        for (RefreshTokenEntity token : tokens.findByFamily(familyId)) token.revoke(now);
    }

    private void markFamilyReused(String familyId, Instant now) {
        if (familyId == null) return;
        for (RefreshTokenEntity token : tokens.findByFamily(familyId)) token.markReused(now);
    }

    private static String randomToken() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String normalizeClientId(String value) {
        String normalized = value == null || value.isBlank() ? DEFAULT_CLIENT_ID : value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) throw new IllegalArgumentException("invalid clientId");
        return normalized;
    }

    private static String hash(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public record CreatedSession(String refreshToken, String accessTokenId, String sessionId,
                                 Instant refreshExpiresAt, String clientId, String approvedScope) {
    }

    public record RotatedSession(UserRepository.AuthUser user, String refreshToken, String accessTokenId,
                                 String sessionId, Instant refreshExpiresAt, String clientId, String approvedScope) {
    }

    public record OnlineSession(String sessionId, String userId, String username, String displayName,
                                String ipAddress, Instant createdAt, Instant expiresAt, Instant accessExpiresAt) {
    }
}
