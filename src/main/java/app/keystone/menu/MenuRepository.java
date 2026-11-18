package app.keystone.menu;

import app.keystone.auth.ApiKeyRoleEntity;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import app.keystone.auth.ApiKeyPermissionEntity;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** 菜单管理入口；具体持久化由 Panache Repository 负责。 */
@ApplicationScoped
public class MenuRepository implements PanacheRepositoryBase<MenuEntity, java.util.UUID> {
    @Inject MenuRoleOrmRepository roles;
    @Inject MenuPermissionOrmRepository permissions;
    @Inject AuthorizationService authorization;

    @Transactional
    public List<Menu> listForRoles(AuthorizationContext context, List<String> roleCodes) {
        authorization.require(context, "menu:read", "menu");
        if (roleCodes == null || roleCodes.isEmpty()) return List.of();
        return find("select distinct m from MenuEntity m join m.roles role "
                        + "where m.enabled = true and role.code in ?1 "
                        + "order by m.parentId, m.sortOrder, m.id", roleCodes)
                .list().stream().map(MenuEntity::toModel).toList();
    }

    /** 管理主体读取完整菜单目录；停用菜单和未绑定角色的节点也必须保留。 */
    @Transactional
    public List<Menu> listForManagement(AuthorizationContext context) {
        authorization.require(context, "menu:manage", "menu");
        return find("order by parentId, sortOrder, id").list().stream().map(MenuEntity::toModel).toList();
    }

    @Transactional
    public Menu create(AuthorizationContext context, MenuRequest request) {
        return create(context, request, request.permission() != null);
    }

    @Transactional
    public Menu create(AuthorizationContext context, MenuRequest request, boolean permissionSpecified) {
        authorization.require(context, "menu:create", "menu");
        if (permissionSpecified) authorization.require(context, "menu:manage", "menu");
        require(request.code(), "code");
        require(request.name(), "name");
        ApiKeyPermissionEntity permission = permissionSpecified ? resolvePermission(request.permission()) : null;
        try {
            MenuEntity entity = new MenuEntity(request);
            if (permissionSpecified) entity.replacePermission(permission);
            persistAndFlush(entity);
            return entity.toModel();
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("menu code already exists or parent does not exist", e);
            throw new IllegalStateException("Could not create menu", e);
        }
    }

    @Transactional
    public Menu update(AuthorizationContext context, String id, MenuRequest request) {
        return update(context, id, request, request.permission() != null);
    }

    @Transactional
    public Menu update(AuthorizationContext context, String id, MenuRequest request, boolean permissionSpecified) {
        authorization.require(context, "menu:update", "menu");
        if (permissionSpecified) authorization.require(context, "menu:manage", "menu");
        var menuId = parseMenuId(id);
        MenuEntity entity = find("id", menuId).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("menu not found");
        var parentId = parseParentId(request.parentId());
        validateParent(menuId, parentId);
        ApiKeyPermissionEntity permission = permissionSpecified ? resolvePermission(request.permission()) : null;
        entity.update(request, parentId);
        if (permissionSpecified) entity.replacePermission(permission);
        return entity.toModel();
    }

    private ApiKeyPermissionEntity resolvePermission(String value) {
        if (value == null || value.isBlank()) return null;
        ApiKeyPermissionEntity permission = permissions.findAssignableByCode(value.trim());
        if (permission == null) throw new IllegalArgumentException("permission not found");
        return permission;
    }

    @Transactional
    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "menu:delete", "menu");
        MenuEntity entity = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("menu not found");
        try {
            delete(entity);
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("menu has child menus", e);
            throw e;
        }
    }

    @Transactional
    public void assignRoles(AuthorizationContext context, String menuId, List<String> roleCodes) {
        authorization.require(context, "menu:manage", "menu");
        MenuEntity menu = find("id", app.keystone.identity.UuidValues.parse(menuId)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (menu == null) throw new java.util.NoSuchElementException("menu not found");
        var normalized = new LinkedHashSet<String>();
        for (String code : roleCodes == null ? List.<String>of() : roleCodes) {
            if (code != null && !code.isBlank()) normalized.add(code.trim());
        }
        List<String> alreadyBoundCodes = menu.roles().stream().map(ApiKeyRoleEntity::codeValue).toList();
        List<ApiKeyRoleEntity> found = roles.findAssignableByCodes(List.copyOf(normalized), alreadyBoundCodes);
        if (found.size() != normalized.size()) {
            throw new IllegalArgumentException("unknown role");
        }
        menu.replaceRoles(new LinkedHashSet<>(found));
    }

    /** 读取菜单当前绑定的角色编码，供管理端保存前确认现有关系。 */
    @Transactional
    public List<String> roleCodes(AuthorizationContext context, String menuId) {
        authorization.require(context, "menu:manage", "menu");
        MenuEntity menu = find("id", app.keystone.identity.UuidValues.parse(menuId)).firstResult();
        if (menu == null) throw new java.util.NoSuchElementException("menu not found");
        return menu.roles().stream().map(ApiKeyRoleEntity::codeValue).sorted().toList();
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static java.util.UUID parseMenuId(String value) {
        try {
            return app.keystone.identity.UuidValues.parse(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("id must be a UUID", e);
        }
    }

    private static java.util.UUID parseParentId(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return app.keystone.identity.UuidValues.parse(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("parentId must be a UUID", e);
        }
    }

    /** 检查父级存在，并沿父链拒绝自身或后代节点，避免形成菜单环。 */
    private void validateParent(java.util.UUID menuId, java.util.UUID parentId) {
        var visited = new java.util.HashSet<java.util.UUID>();
        var currentId = parentId;
        while (currentId != null) {
            if (!visited.add(currentId)) throw new IllegalArgumentException("menu parent cycle detected");
            if (menuId.equals(currentId)) throw new IllegalArgumentException("menu cannot be nested under its descendant");
            MenuEntity parent = findById(currentId);
            if (parent == null) throw new IllegalArgumentException("parent menu does not exist");
            currentId = parent.parentId();
        }
    }

    private static boolean isConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("foreign key")) return true;
        }
        return false;
    }

    public record MenuRequest(String parentId, String code, String name, String path, String component,
                              String menuType, String permission, Integer sortOrder, Boolean enabled) {
    }
}
