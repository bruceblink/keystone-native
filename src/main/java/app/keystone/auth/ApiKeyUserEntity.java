package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import app.keystone.user.User;
import app.keystone.user.UserRepository;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import app.keystone.identity.UuidBinaryConverter;
import java.util.UUID;

/** 映射 API Key 认证和签发所需的用户状态及权限关系。 */
@Entity
@Table(name = "sys_user")
public class ApiKeyUserEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 64)
    private String username;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "display_name", nullable = false, length = 128)
    private String displayName;

    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount;

    @Column(name = "locked_until")
    private java.time.Instant lockedUntil;

    @Column(name = "credential_version", nullable = false)
    private long credentialVersion;

    @Column(name = "last_password_changed_at")
    private java.time.Instant lastPasswordChangedAt;

    @Column(name = "mfa_required", nullable = false)
    private boolean mfaRequired;

    @Column(name = "mfa_grace_until")
    private java.time.Instant mfaGraceUntil;

    @Column(name = "dept_id")
    @Convert(converter = UuidBinaryConverter.class)
    private String deptId;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "post_id", columnDefinition = "BINARY(16)")
    private UUID postId;

    @Column(length = 128)
    private String email;

    @Column(name = "oidc_issuer", length = 255)
    private String oidcIssuer;

    @Column(name = "oidc_subject", length = 255)
    private String oidcSubject;

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

    /** 创建用户实体；调用方必须在同一事务内绑定已经校验过的启用角色。 */
    ApiKeyUserEntity(String username, String passwordHash, String displayName, String deptId, String postId,
                     String email, String phoneNumber, Integer sex, String avatar, String remark) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.username = username;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
        this.deptId = deptId;
        this.postId = postId == null ? null : app.keystone.identity.UuidValues.parse(postId);
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.sex = sex;
        this.avatar = avatar;
        this.remark = remark;
        this.enabled = true;
        this.failedLoginCount = 0;
        this.credentialVersion = 1;
        this.permissionVersion = 1;
    }

    String username() {
        return username;
    }

    boolean enabled() {
        return enabled;
    }

    String id() {
        return id == null ? null : id.toString();
    }

    String displayName() {
        return displayName;
    }

    String oidcIssuer() {
        return oidcIssuer;
    }

    String oidcSubject() {
        return oidcSubject;
    }

    String loginIp() {
        return loginIp;
    }

    /** 更新登录元数据；调用方必须在事务内持有该实体。 */
    void markLogin(String ipAddress, java.time.Instant at) {
        loginIp = ipAddress;
        loginAt = at;
    }

    long permissionVersion() {
        return permissionVersion;
    }

    String departmentId() {
        return deptId;
    }

    Set<ApiKeyRoleEntity> roles() {
        return roles;
    }

    boolean mfaRequired() {
        return mfaRequired;
    }

    java.time.Instant mfaGraceUntil() {
        return mfaGraceUntil;
    }

    void setMfaRequired(boolean required) {
        mfaRequired = required;
    }

    String passwordHash() {
        return passwordHash;
    }

    int failedLoginCount() {
        return failedLoginCount;
    }

    java.time.Instant lockedUntil() {
        return lockedUntil;
    }

    /** 更新密码及凭据版本；调用方必须在用户行写锁事务内调用。 */
    void changePassword(String newPasswordHash, java.time.Instant changedAt) {
        passwordHash = newPasswordHash;
        mustChangePassword = false;
        failedLoginCount = 0;
        lockedUntil = null;
        credentialVersion++;
        lastPasswordChangedAt = changedAt;
    }

    /** 记录一次错误密码尝试；调用方必须在用户行写锁事务内调用。 */
    void recordFailedLogin(int attempts, java.time.Instant newLockedUntil) {
        failedLoginCount = attempts;
        lockedUntil = newLockedUntil;
    }

    /** 成功认证后清除失败次数和临时锁定时间。 */
    void clearFailedLogins() {
        failedLoginCount = 0;
        lockedUntil = null;
    }

    Set<String> permissions() {
        return roles.stream()
                .filter(ApiKeyRoleEntity::enabled)
                .flatMap(role -> role.permissions().stream())
                .map(ApiKeyPermissionEntity::code)
                .collect(Collectors.toUnmodifiableSet());
    }

    /** 替换用户角色集合；调用方必须在事务内传入已加载的启用角色。 */
    void replaceRoles(Set<ApiKeyRoleEntity> replacement) {
        roles.clear();
        roles.addAll(replacement);
    }

    boolean addRole(ApiKeyRoleEntity role) {
        return roles.add(role);
    }

    boolean removeRole(ApiKeyRoleEntity role) {
        return roles.remove(role);
    }

    boolean hasRole(ApiKeyRoleEntity role) {
        return roles.contains(role);
    }

    /** 更新用户资料字段；调用方必须在用户行写锁事务内调用。 */
    void updateProfile(String newDisplayName, boolean updateDept, String newDeptId, String newPostId,
                       String newEmail, String newPhoneNumber, Integer newSex, String newAvatar,
                       String newRemark, Boolean newEnabled) {
        if (newDisplayName != null && !newDisplayName.isBlank()) displayName = newDisplayName.trim();
        if (updateDept) deptId = newDeptId;
        if (newPostId != null) postId = app.keystone.identity.UuidValues.parse(newPostId);
        if (newEmail != null) email = emptyToNull(newEmail);
        if (newPhoneNumber != null) phoneNumber = emptyToNull(newPhoneNumber);
        if (newSex != null) sex = newSex;
        if (newAvatar != null) avatar = emptyToNull(newAvatar);
        if (newRemark != null) remark = emptyToNull(newRemark);
        if (newEnabled != null) enabled = newEnabled;
    }

    /** 角色集合发生写入时递增权限版本，使旧访问令牌立即失效。 */
    void bumpPermissionVersion() {
        permissionVersion++;
    }

    private static String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    UserRepository.AuthUser toAuthUser() {
        var roleCodes = roles.stream().filter(ApiKeyRoleEntity::enabled).map(ApiKeyRoleEntity::code).sorted().toList();
        return new UserRepository.AuthUser(id(), username, displayName,
                roleCodes,
                mustChangePassword, deptId, postId == null ? null : postId.toString(), email, phoneNumber, sex, avatar, loginIp, loginAt, remark);
    }

    /** 转换为用户管理接口返回的公开字段，不包含密码和凭据版本。 */
    User toUser() {
        var roleCodes = roles.stream().filter(ApiKeyRoleEntity::enabled).map(ApiKeyRoleEntity::code).sorted().toList();
        return new User(id(), username, displayName, deptId, postId == null ? null : postId.toString(), enabled,
                email, phoneNumber, sex, avatar, loginIp, loginAt, remark,
                roleCodes);
    }
}
