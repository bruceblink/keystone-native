package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.UUID;

/** 通过 ORM 读取角色权限绑定所需的权限记录。 */
@ApplicationScoped
class ApiKeyPermissionRepository implements PanacheRepositoryBase<ApiKeyPermissionEntity, UUID> {
    /** 角色新授权只接受启用且未废弃的目录项。 */
    List<ApiKeyPermissionEntity> findAssignableByCodes(List<String> codes) {
        if (codes == null || codes.isEmpty()) return List.of();
        return find("code in ?1 and status = 1 and deprecated = false", codes).list();
    }
}
