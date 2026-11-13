package app.keystone.menu;

import app.keystone.auth.ApiKeyRoleEntity;
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
public class MenuRepository implements PanacheRepositoryBase<MenuEntity, Long> {
    @Inject MenuRoleOrmRepository roles;

    @Transactional
    public List<Menu> listForRoles(List<String> roleCodes) {
        if (roleCodes == null || roleCodes.isEmpty()) return List.of();
        return find("select distinct m from MenuEntity m join m.roles role "
                        + "where m.enabled = true and role.code in ?1 "
                        + "order by coalesce(m.parentId, 0), m.sortOrder, m.id", roleCodes)
                .list().stream().map(MenuEntity::toModel).toList();
    }

    @Transactional
    public Menu create(MenuRequest request) {
        require(request.code(), "code");
        require(request.name(), "name");
        try {
            MenuEntity entity = new MenuEntity(request);
            persistAndFlush(entity);
            return entity.toModel();
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("menu code already exists or parent does not exist", e);
            throw new IllegalStateException("Could not create menu", e);
        }
    }

    @Transactional
    public Menu update(long id, MenuRequest request) {
        MenuEntity entity = find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("menu not found");
        entity.update(request);
        return entity.toModel();
    }

    @Transactional
    public void delete(long id) {
        MenuEntity entity = find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (entity == null) throw new java.util.NoSuchElementException("menu not found");
        try {
            delete(entity);
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("menu has child menus", e);
            throw e;
        }
    }

    @Transactional
    public void assignRoles(long menuId, List<String> roleCodes) {
        MenuEntity menu = find("id", menuId).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (menu == null) throw new java.util.NoSuchElementException("menu not found");
        var normalized = new LinkedHashSet<String>();
        for (String code : roleCodes == null ? List.<String>of() : roleCodes) {
            if (code != null && !code.isBlank()) normalized.add(code.trim());
        }
        List<ApiKeyRoleEntity> found = roles.findEnabledByCodes(List.copyOf(normalized));
        if (found.size() != normalized.size()) {
            throw new IllegalArgumentException("unknown role");
        }
        menu.replaceRoles(new LinkedHashSet<>(found));
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static boolean isConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("foreign key")) return true;
        }
        return false;
    }

    public record MenuRequest(Long parentId, String code, String name, String path, String component,
                              String menuType, String permission, Integer sortOrder, Boolean enabled) {
    }
}
