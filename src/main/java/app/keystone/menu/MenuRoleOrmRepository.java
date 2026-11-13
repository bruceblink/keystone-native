package app.keystone.menu;

import app.keystone.auth.ApiKeyRoleEntity;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;

/** 读取菜单角色绑定所需的启用角色。 */
@ApplicationScoped
class MenuRoleOrmRepository implements PanacheRepositoryBase<ApiKeyRoleEntity, Long> {
    List<ApiKeyRoleEntity> findEnabledByCodes(List<String> codes) {
        return find("code in ?1 and enabled = true", codes).list();
    }
}
