package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import io.quarkus.panache.common.Sort;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import app.keystone.identity.UuidValues;

/** 使用 Panache 管理 API Key 主记录，密钥明文只在签发结果中返回一次。 */
@ApplicationScoped
public class ApiKeyRepository implements PanacheRepository<ApiKeyEntity> {
    private final SecureRandom random = new SecureRandom();

    @Inject ApiKeyUserRepository users;
    @Inject ServiceSubjectRepository subjects;

    /** 多节点部署使用参数化 HQL 条件更新，避免本地缓存造成重复写入。 */
    @ConfigProperty(name = "keystone.security.api-key.last-used-update-interval-seconds", defaultValue = "60")
    long lastUsedUpdateIntervalSeconds;

    @Transactional
    public IssuedApiKey issue(String userId, String name, List<String> scopes, Instant expiresAt) {
        validateIssue(name, expiresAt);
        List<String> normalizedScopes = normalizeScopes(scopes);
        if (normalizedScopes.isEmpty()) throw new IllegalArgumentException("at least one scope is required");
        Set<String> allowed = new HashSet<>(users.permissions(userId));
        if (!allowed.containsAll(normalizedScopes)) throw new IllegalArgumentException("scope exceeds issuer permissions");

        String secret = random(32);
        String prefix = random(8);
        String value = "ks_live_" + prefix + "_" + secret;
        String id = UuidValues.v7();
        String subjectId = ensureSubject(userId);
        persistAndFlush(new ApiKeyEntity(id, userId, subjectId, userId, name.trim(), prefix, hash(value),
                String.join(" ", normalizedScopes), expiresAt));
        return new IssuedApiKey(id, name.trim(), prefix, value, normalizedScopes, expiresAt);
    }

    /** 在同一事务内核验密钥、主体状态和用户状态，并以条件更新节流最后使用时间。 */
    @Transactional
    public Principal authenticate(String value) {
        if (value == null || value.isBlank()) return null;
        Instant now = Instant.now();
        ApiKeyEntity key = find("keyHash = ?1 and revokedAt is null and (expiresAt is null or expiresAt > ?2)",
                hash(value), now).firstResult();
        if (key == null) return null;
        if (key.subjectId() == null) return null;
        ServiceSubjectEntity subject = subjects.findById(UuidValues.parse(key.subjectId()));
        if (subject == null || !subject.enabled()) return null;
        ApiKeyUserEntity user = users.findEnabled(key.userId());
        if (user == null) return null;
        touchLastUsed(key.id());
        return new Principal(key.id(), key.subjectId(), key.userId(), user.username(), split(key.scopes()));
    }

    /** 只在达到最小间隔后更新使用时间，条件更新由数据库原子执行。 */
    private void touchLastUsed(String keyId) {
        long interval = lastUsedUpdateIntervalSeconds();
        Instant now = Instant.now();
        update("lastUsedAt = ?1 where id = ?2 and (lastUsedAt is null or lastUsedAt <= ?3)",
                now, UuidValues.parse(keyId), now.minusSeconds(interval));
    }

    private long lastUsedUpdateIntervalSeconds() {
        if (lastUsedUpdateIntervalSeconds < 0) {
            throw new IllegalStateException("API key last-used update interval must be non-negative");
        }
        return lastUsedUpdateIntervalSeconds;
    }

    @Transactional
    public void revoke(String userId, String id) {
        Instant now = Instant.now();
        long updated = update("revokedAt = coalesce(revokedAt, ?1), revokedReason = coalesce(revokedReason, ?2) "
                        + "where id = ?3 and userId = ?4",
                now, "revoked by owner", UuidValues.parse(id), userId);
        if (updated == 0) throw new NoSuchElementException("API key not found");
    }

    public List<ApiKeyMetadata> list(String userId) {
        return find("userId", Sort.by("createdAt", Sort.Direction.Descending), userId)
                .list().stream()
                .map(this::metadata)
                .toList();
    }

    /** 锁定旧记录后写入新密钥并撤销旧密钥，整个轮换过程由一个事务完成。 */
    @Transactional
    public IssuedApiKey rotate(String userId, String id) {
        ApiKeyEntity current = find("id = ?1 and userId = ?2", UuidValues.parse(id), userId)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
        if (current == null) throw new NoSuchElementException("API key not found");
        if (current.revokedAt() != null) throw new IllegalArgumentException("API key is already revoked");

        String secret = random(32);
        String prefix = random(8);
        String value = "ks_live_" + prefix + "_" + secret;
        String replacementId = UuidValues.v7();
        List<String> scopes = split(current.scopes());
        persistAndFlush(new ApiKeyEntity(replacementId, userId, current.subjectId(), userId, current.name(), prefix,
                hash(value), String.join(" ", scopes), current.expiresAt()));
        current.revoke(Instant.now(), "rotated", replacementId);
        flush();
        return new IssuedApiKey(replacementId, current.name(), prefix, value, scopes, current.expiresAt());
    }

    private String ensureSubject(String userId) {
        String code = "user:" + userId;
        ServiceSubjectEntity existing = subjects.findByCode(code);
        if (existing != null) return existing.id();
        String id = UuidValues.v7();
        subjects.persistAndFlush(new ServiceSubjectEntity(id, code, "User API keys: " + userId, userId));
        return id;
    }

    private ApiKeyMetadata metadata(ApiKeyEntity key) {
        return new ApiKeyMetadata(key.id(), key.name(), key.keyPrefix(), split(key.scopes()), key.expiresAt(),
                key.revokedAt(), key.lastUsedAt(), key.createdAt());
    }

    private static void validateIssue(String name, Instant expiresAt) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("name is required");
        if (name.trim().length() > 128) throw new IllegalArgumentException("name is too long");
        Instant now = Instant.now();
        if (expiresAt != null && (expiresAt.isBefore(now) || expiresAt.isAfter(now.plusSeconds(90L * 24 * 3600)))) {
            throw new IllegalArgumentException("expiresAt must be within 90 days");
        }
    }

    private static List<String> normalizeScopes(Collection<String> scopes) {
        if (scopes == null) return List.of();
        return scopes.stream()
                .filter(s -> s != null && !s.isBlank())
                .map(String::trim)
                .map(String::toLowerCase)
                .distinct()
                .sorted()
                .peek(s -> {
                    if (!s.matches("[a-z0-9][a-z0-9._-]*:[a-z0-9][a-z0-9._-]*")) {
                        throw new IllegalArgumentException("invalid scope: " + s);
                    }
                })
                .toList();
    }

    private static List<String> split(String value) {
        return value == null || value.isBlank() ? List.of() : List.of(value.split(" "));
    }

    private String random(int bytes) {
        byte[] value = new byte[bytes];
        random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String hash(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public record IssuedApiKey(String id, String name, String prefix, String apiKey, List<String> scopes,
                               Instant expiresAt) {
    }

    public record Principal(String keyId, String subjectId, String userId, String username, List<String> scopes) {
    }

    public record ApiKeyMetadata(String id, String name, String prefix, List<String> scopes, Instant expiresAt,
                                 Instant revokedAt, Instant lastUsedAt, Instant createdAt) {
    }
}
