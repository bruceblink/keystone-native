package app.keystone.auth;

import io.quarkus.runtime.Startup;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.time.Instant;
import java.util.List;

/** 以数据库登记记录作为 JWK 发布目录，并在启动时同步配置中的公钥。 */
@Startup
@ApplicationScoped
public class JwtKeyRegistryService {
    @Inject JwtKeyRegistryRepository repository;
    @Inject JwkSetService configuredKeys;
    @ConfigProperty(name = "keystone.security.jwt.registry.expiry-days", defaultValue = "30")
    int defaultRetiringDays;

    void onStart(@Observes StartupEvent ignored) {
        syncConfiguredKeys();
    }

    /** 将配置校验后的公钥登记到数据库；已有 RETIRING 状态不会被无意恢复。 */
    public void syncConfiguredKeys() {
        List<JwkSetService.RsaJwk> keys = configuredKeys.current().keys();
        String currentKeyId = keys.get(0).kid();
        for (JwkSetService.RsaJwk key : keys) {
            JwtKeyRegistryEntity existing = repository.findByKeyId(key.kid());
            String state = existing == null ? RegistryState.ACTIVE : existing.state();
            if (key.kid().equals(currentKeyId) && RegistryState.RETIRING.equals(state)) {
                throw new IllegalStateException("current JWT signing key cannot be retiring");
            }
            repository.upsert(key, state, existing == null ? null : existing.expiresAt());
        }
        if (repository.findUsable(Instant.now()).stream().noneMatch(key -> key.keyId().equals(currentKeyId))) {
            throw new IllegalStateException("current JWT signing key is not registered or usable");
        }
    }

    /** 返回未到期的 active/retiring JWK，过期记录不会再次发布。 */
    public JwkSetService.JwkSet current() {
        Instant now = Instant.now();
        List<JwkSetService.RsaJwk> keys = repository.findUsable(now).stream()
                .map(key -> new JwkSetService.RsaJwk("RSA", key.keyId(), "RS256", "sig", key.modulus(), key.exponent()))
                .toList();
        if (keys.isEmpty()) throw new IllegalStateException("JWT public key registry is empty");
        return new JwkSetService.JwkSet(keys);
    }

    public boolean accepts(String keyId) {
        try {
            JwtKeyRegistryEntity key = repository.findByKeyId(keyId);
            return key != null && RegistryState.usable(key.state(), key.expiresAt(), Instant.now());
        } catch (RuntimeException error) {
            throw new IllegalStateException("JWT key registry is unavailable", error);
        }
    }

    public void retire(String keyId, Instant expiresAt) {
        if (expiresAt == null || !expiresAt.isAfter(Instant.now())) {
            throw new IllegalArgumentException("retiring JWT key requires a future expiry");
        }
        repository.retire(keyId, expiresAt, Instant.now());
    }

    public int purgeExpired() {
        return repository.purgeExpired(Instant.now());
    }

    /** 每小时清理已经超过保留期限的旧公钥，避免 registry 无限增长。 */
    @Scheduled(every = "1h", identity = "jwt-key-registry-cleanup")
    void scheduledCleanup() {
        purgeExpired();
    }

    public int defaultRetiringDays() {
        if (defaultRetiringDays < 1 || defaultRetiringDays > 3650) {
            throw new IllegalStateException("JWT registry expiry days must be between 1 and 3650");
        }
        return defaultRetiringDays;
    }
}
