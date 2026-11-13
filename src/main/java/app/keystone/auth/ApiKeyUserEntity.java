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
import java.util.stream.Collectors;

/** 映射 API Key 认证和签发所需的用户状态及权限关系。 */
@Entity
@Table(name = "sys_user")
public class ApiKeyUserEntity {
    @Id
    private Long id;

    @Column(nullable = false, length = 64)
    private String username;

    @Column(nullable = false)
    private boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "sys_user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<ApiKeyRoleEntity> roles = new HashSet<>();

    protected ApiKeyUserEntity() {
    }

    String username() {
        return username;
    }

    boolean enabled() {
        return enabled;
    }

    Set<String> permissions() {
        return roles.stream()
                .filter(ApiKeyRoleEntity::enabled)
                .flatMap(role -> role.permissions().stream())
                .map(ApiKeyPermissionEntity::code)
                .collect(Collectors.toUnmodifiableSet());
    }
}
