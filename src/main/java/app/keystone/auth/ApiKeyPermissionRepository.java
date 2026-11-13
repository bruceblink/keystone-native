package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.UUID;

/** 通过 ORM 读取角色权限绑定所需的权限记录。 */
@ApplicationScoped
class ApiKeyPermissionRepository implements PanacheRepositoryBase<ApiKeyPermissionEntity, UUID> {
    List<ApiKeyPermissionEntity> findByCodes(List<String> codes) {
        if (codes == null || codes.isEmpty()) return List.of();
        return find("code in ?1", codes).list();
    }
}
