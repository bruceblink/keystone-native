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
import app.keystone.user.UserRepository;

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

    @Column(name = "display_name", nullable = false, length = 128)
    private String displayName;

    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword;

    @Column(name = "dept_id")
    private Long deptId;

    @Column(name = "post_id")
    private Long postId;

    @Column(length = 128)
    private String email;

    @Column(name = "phone_number", length = 32)
    private String phoneNumber;

    @Column
    private Integer sex;

    @Column(length = 512)
    private String avatar;

    @Column(name = "login_ip", length = 64)
    private String loginIp;

    @Column(name = "login_at")
    private java.time.Instant loginAt;

    @Column(name = "permission_version", nullable = false)
    private long permissionVersion;

    @Column(length = 500)
    private String remark;

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

    long id() {
        return id;
    }

    String displayName() {
        return displayName;
    }

    String loginIp() {
        return loginIp;
    }

    long permissionVersion() {
        return permissionVersion;
    }

    Set<String> permissions() {
        return roles.stream()
                .filter(ApiKeyRoleEntity::enabled)
                .flatMap(role -> role.permissions().stream())
                .map(ApiKeyPermissionEntity::code)
                .collect(Collectors.toUnmodifiableSet());
    }

    UserRepository.AuthUser toAuthUser() {
        var roleCodes = roles.stream().filter(ApiKeyRoleEntity::enabled).map(ApiKeyRoleEntity::code).sorted().toList();
        return new UserRepository.AuthUser(id, username, displayName,
                roleCodes.isEmpty() ? java.util.List.of("USER") : roleCodes,
                mustChangePassword, deptId, postId, email, phoneNumber, sex, avatar, loginIp, loginAt, remark);
    }
}
