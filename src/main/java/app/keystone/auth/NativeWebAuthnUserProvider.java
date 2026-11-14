package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.security.webauthn.WebAuthnCredentialRecord;
import io.quarkus.security.webauthn.WebAuthnUserProvider;
import io.smallrye.common.annotation.Blocking;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/** 为 Quarkus WebAuthn 校验提供数据库凭据，并保持计数器单调增加。 */
@Blocking
@ApplicationScoped
public class NativeWebAuthnUserProvider
        implements WebAuthnUserProvider, PanacheRepositoryBase<WebAuthnCredentialEntity, String> {
    @jakarta.inject.Inject ApiKeyUserRepository users;

    @Override
    @Transactional
    public Uni<List<WebAuthnCredentialRecord>> findByUsername(String username) {
        if (username == null || username.isBlank()) return Uni.createFrom().item(List.of());
        return Uni.createFrom().item(find("username = ?1", username.trim()).list().stream()
                .map(WebAuthnCredentialEntity::toRecord).toList());
    }

    @Override
    @Transactional
    public Uni<WebAuthnCredentialRecord> findByCredentialId(String credentialId) {
        WebAuthnCredentialEntity credential = findById(credentialId);
        if (credential == null) return Uni.createFrom().failure(new IllegalArgumentException("credential not found"));
        return Uni.createFrom().item(credential.toRecord());
    }

    /** 只允许为已经存在的本地用户保存凭据；注册入口会先要求人类会话。 */
    @Override
    @Transactional
    public Uni<Void> store(WebAuthnCredentialRecord record) {
        if (record == null || record.getUsername() == null || record.getUsername().isBlank()) {
            return Uni.createFrom().failure(new IllegalArgumentException("invalid credential"));
        }
        ApiKeyUserEntity user = users.find("username = ?1 and enabled = true", record.getUsername().trim()).firstResult();
        if (user == null) return Uni.createFrom().failure(new IllegalArgumentException("user not found"));
        if (findById(record.getCredentialID()) != null) {
            return Uni.createFrom().failure(new IllegalArgumentException("credential already exists"));
        }
        persistAndFlush(new WebAuthnCredentialEntity(record, UUID.fromString(user.id()), user.username()));
        return Uni.createFrom().voidItem();
    }

    /** 计数器在锁内更新，拒绝非零计数器回退，降低凭据复制重放风险。 */
    @Override
    @Transactional
    public Uni<Void> update(String credentialId, long nextCounter) {
        WebAuthnCredentialEntity credential = find("credentialId", credentialId)
                .withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (credential == null) return Uni.createFrom().failure(new IllegalArgumentException("credential not found"));
        if (credential.counter() > 0 && nextCounter <= credential.counter()) {
            return Uni.createFrom().failure(new IllegalArgumentException("invalid authenticator counter"));
        }
        credential.updateCounter(nextCounter);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Set<String> getRoles(String username) {
        if (username == null || username.isBlank()) return Set.of();
        return users.findAuthUserByUsername(username.trim())
                .map(user -> Set.copyOf(user.roles()))
                .orElseGet(Set::of);
    }
}
