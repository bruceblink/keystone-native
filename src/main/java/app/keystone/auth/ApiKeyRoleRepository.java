package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.UUID;

/** 通过 ORM 读取用户创建和授权所需的启用角色。 */
@ApplicationScoped
class ApiKeyRoleRepository implements PanacheRepositoryBase<ApiKeyRoleEntity, java.util.UUID> {
    List<ApiKeyRoleEntity> findEnabledByCodes(List<String> codes) {
        return find("code in ?1 and enabled = true", codes).list();
    }

    /** 按导入文件中的 UUID 读取启用角色；返回数量由调用方核对以拒绝未知角色。 */
    List<ApiKeyRoleEntity> findEnabledByIds(List<UUID> ids) {
        return find("id in ?1 and enabled = true", ids).list();
    }
}
