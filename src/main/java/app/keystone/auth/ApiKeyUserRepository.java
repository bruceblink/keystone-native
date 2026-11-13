package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Set;

/** 通过 ORM 读取 API Key 认证主体和签发权限。 */
@ApplicationScoped
public class ApiKeyUserRepository implements PanacheRepositoryBase<ApiKeyUserEntity, Long> {

    ApiKeyUserEntity findEnabled(long userId) {
        ApiKeyUserEntity user = find("id = ?1 and enabled = true", userId).firstResult();
        return user != null && user.enabled() ? user : null;
    }

    Set<String> permissions(long userId) {
        ApiKeyUserEntity user = findEnabled(userId);
        return user == null ? Set.of() : user.permissions();
    }
}
