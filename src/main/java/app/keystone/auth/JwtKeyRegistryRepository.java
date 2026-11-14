package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import java.time.Instant;
import java.util.List;

/** 使用 ORM 保存和查询可发布的 JWT 公钥目录。 */
@ApplicationScoped
public class JwtKeyRegistryRepository implements PanacheRepositoryBase<JwtKeyRegistryEntity, java.util.UUID> {
    public JwtKeyRegistryEntity findByKeyId(String keyId) {
        return find("keyId", RegistryState.requireKeyId(keyId)).firstResult();
    }

    public List<JwtKeyRegistryEntity> findUsable(Instant now) {
        return find("state in (?1, ?2) and (expiresAt is null or expiresAt > ?3) order by keyId",
                RegistryState.ACTIVE, RegistryState.RETIRING, now).list();
    }

    @Transactional
    public JwtKeyRegistryEntity upsert(JwkSetService.RsaJwk key, String state, Instant expiresAt) {
        String keyId = RegistryState.requireKeyId(key.kid());
        JwtKeyRegistryEntity existing = findByKeyId(keyId);
        if (existing == null) {
            existing = new JwtKeyRegistryEntity(keyId, key.n(), key.e(), state, expiresAt);
            persistAndFlush(existing);
        } else {
            existing.refresh(key.n(), key.e(), state, expiresAt);
            persistAndFlush(existing);
        }
        return existing;
    }

    @Transactional
    public void retire(String keyId, Instant expiresAt, Instant now) {
        JwtKeyRegistryEntity key = findByKeyId(keyId);
        if (key == null) throw new IllegalArgumentException("JWT key is not registered");
        key.retire(now, expiresAt);
        persistAndFlush(key);
    }

    @Transactional
    public int purgeExpired(Instant now) {
        return Math.toIntExact(delete("expiresAt is not null and expiresAt <= ?1", now));
    }
}
