package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;

/** 通过 ORM 读取用户创建和授权所需的启用角色。 */
@ApplicationScoped
class ApiKeyRoleRepository implements PanacheRepositoryBase<ApiKeyRoleEntity, java.util.UUID> {
    List<ApiKeyRoleEntity> findEnabledByCodes(List<String> codes) {
        return find("code in ?1 and enabled = true", codes).list();
    }
}
