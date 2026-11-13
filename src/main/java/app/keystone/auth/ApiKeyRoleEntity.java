package app.keystone.auth;

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

/** 映射 API Key 签发所需的已启用角色和权限关系。 */
@Entity
@Table(name = "sys_role")
public class ApiKeyRoleEntity {
    @Id
    private Long id;

    @Column(nullable = false)
    private boolean enabled;

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

    Set<ApiKeyPermissionEntity> permissions() {
        return permissions;
    }
}
