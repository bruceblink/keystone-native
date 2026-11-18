package app.keystone.menu;

import app.keystone.auth.ApiKeyRoleEntity;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;

/** 查询可新增的启用角色，以及菜单已经绑定的停用角色。 */
@ApplicationScoped
class MenuRoleOrmRepository implements PanacheRepositoryBase<ApiKeyRoleEntity, java.util.UUID> {
    List<ApiKeyRoleEntity> findAssignableByCodes(List<String> codes, List<String> alreadyBoundCodes) {
        if (codes.isEmpty()) return List.of();
        if (alreadyBoundCodes.isEmpty()) return find("code in ?1 and enabled = true", codes).list();
        return find("code in ?1 and (enabled = true or code in ?2)", codes, alreadyBoundCodes).list();
    }
}
