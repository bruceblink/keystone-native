package app.keystone.menu;

import app.keystone.auth.ApiKeyPermissionEntity;
import app.keystone.auth.PermissionCatalog;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.UUID;

/** 查询菜单可选权限，并拒绝目录中停用或废弃的标识。 */
@ApplicationScoped
class MenuPermissionOrmRepository implements PanacheRepositoryBase<ApiKeyPermissionEntity, UUID> {
    ApiKeyPermissionEntity findAssignableByCode(String code) {
        if (!PermissionCatalog.contains(code)) return null;
        return find("code = ?1 and status = 1 and deprecated = false", code).firstResult();
    }
}
