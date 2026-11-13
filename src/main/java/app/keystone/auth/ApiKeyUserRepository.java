package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import jakarta.persistence.LockModeType;

import java.util.Set;

/** 通过 ORM 读取 API Key 认证主体和签发权限。 */
@ApplicationScoped
public class ApiKeyUserRepository implements PanacheRepositoryBase<ApiKeyUserEntity, Long> {

    ApiKeyUserEntity findEnabled(long userId) {
        ApiKeyUserEntity user = find("id = ?1 and enabled = true", userId).firstResult();
        return user != null && user.enabled() ? user : null;
    }

    @Transactional
    Set<String> permissions(long userId) {
        ApiKeyUserEntity user = findEnabled(userId);
        return user == null ? Set.of() : user.permissions();
    }

    @Transactional
    boolean hasPermission(long userId, String permission) {
        return permissions(userId).contains(permission);
    }

    @Transactional
    boolean hasPermissionByUsername(String username, String permission) {
        if (username == null || username.isBlank()) return false;
        ApiKeyUserEntity user = find("username = ?1 and enabled = true", username).firstResult();
        return user != null && user.permissions().contains(permission);
    }

    @Transactional
    long permissionVersion(long userId) {
        ApiKeyUserEntity user = findEnabled(userId);
        return user == null ? -1 : user.permissionVersion();
    }

    ApiKeyUserEntity findEnabledEntity(long userId) {
        return findEnabled(userId);
    }

    ApiKeyUserEntity findForUpdate(long userId) {
        ApiKeyUserEntity user = find("id = ?1 and enabled = true", userId)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
        return user != null && user.enabled() ? user : null;
    }

    java.util.Set<String> permissions(ApiKeyUserEntity user) {
        return user == null ? java.util.Set.of() : user.permissions();
    }
}
