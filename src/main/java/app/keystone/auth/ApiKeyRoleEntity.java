package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.util.HashSet;
import java.util.Set;
import app.keystone.role.Role;

/** 映射 API Key 签发所需的已启用角色和权限关系。 */
@Entity
@Table(name = "sys_role")
public class ApiKeyRoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private boolean enabled;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "data_scope", nullable = false, length = 32)
    private String dataScope;

    @Column(name = "dept_scope", columnDefinition = "TEXT")
    private String deptScope;

    @Column(nullable = false, length = 64)
    private String code;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "sys_role_permission",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<ApiKeyPermissionEntity> permissions = new HashSet<>();

    protected ApiKeyRoleEntity() {
    }

    boolean enabled() {
        return enabled;
    }

    String code() {
        return code;
    }

    long id() {
        return id;
    }

    String name() {
        return name;
    }

    String dataScope() {
        return dataScope;
    }

    String deptScope() {
        return deptScope;
    }

    Set<ApiKeyPermissionEntity> permissions() {
        return permissions;
    }

    /** 创建角色实体；数据库结构仍由 Flyway 管理。 */
    ApiKeyRoleEntity(String code, String name) {
        this.code = code;
        this.name = name;
        this.enabled = true;
        this.dataScope = "ALL";
    }

    void update(String newName, Boolean newEnabled, String newDataScope, String newDeptScope) {
        if (newName != null && !newName.isBlank()) name = newName.trim();
        if (newEnabled != null) enabled = newEnabled;
        if (newDataScope != null && !newDataScope.isBlank()) dataScope = newDataScope.trim().toUpperCase(java.util.Locale.ROOT);
        if (newDeptScope != null) deptScope = newDeptScope;
    }

    void replacePermissions(Set<ApiKeyPermissionEntity> replacement) {
        permissions.clear();
        permissions.addAll(replacement);
    }

    Role toRole() {
        return new Role(id, code, name, enabled, dataScope, deptScope,
                permissions.stream().map(ApiKeyPermissionEntity::code).sorted().toList());
    }
}
