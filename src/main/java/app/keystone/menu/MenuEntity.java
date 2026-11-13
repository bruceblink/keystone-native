package app.keystone.menu;

import app.keystone.auth.ApiKeyRoleEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** 映射菜单及其角色绑定；数据库表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_menu")
public class MenuEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "parent_id", columnDefinition = "BINARY(16)")
    private UUID parentId;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(length = 255)
    private String path;

    @Column(length = 255)
    private String component;

    @Column(name = "menu_type", nullable = false, length = 16)
    private String menuType;

    @Column(length = 128)
    private String permission;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    @Column(nullable = false)
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "sys_role_menu", joinColumns = @JoinColumn(name = "menu_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<ApiKeyRoleEntity> roles = new HashSet<>();

    protected MenuEntity() {
    }

    MenuEntity(MenuRepository.MenuRequest request) {
        id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        parentId = request.parentId() == null ? null : app.keystone.identity.UuidValues.parse(request.parentId());
        code = request.code().trim();
        name = request.name().trim();
        path = request.path();
        component = request.component();
        menuType = request.menuType() == null ? "MENU" : request.menuType();
        permission = request.permission();
        sortOrder = request.sortOrder() == null ? 0 : request.sortOrder();
        enabled = true;
    }

    void update(MenuRepository.MenuRequest request) {
        if (request.name() != null && !request.name().isBlank()) name = request.name().trim();
        if (request.path() != null) path = request.path();
        if (request.component() != null) component = request.component();
        if (request.menuType() != null) menuType = request.menuType();
        if (request.permission() != null) permission = request.permission();
        if (request.sortOrder() != null) sortOrder = request.sortOrder();
        if (request.enabled() != null) enabled = request.enabled();
    }

    void replaceRoles(Set<ApiKeyRoleEntity> replacement) {
        roles.clear();
        roles.addAll(replacement);
    }

    Menu toModel() {
        return new Menu(id == null ? null : id.toString(), parentId == null ? null : parentId.toString(), code, name, path, component, menuType, permission, sortOrder, enabled);
    }
}
