package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

/** 映射权限目录记录，供授权计算、角色绑定和菜单管理共用。 */
@Entity
@Table(name = "sys_permission")
public class ApiKeyPermissionEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 128)
    private String code;

    @Column(nullable = false)
    @JdbcTypeCode(SqlTypes.TINYINT)
    private int status;

    @Column(nullable = false)
    @JdbcTypeCode(SqlTypes.TINYINT)
    private boolean deprecated;

    protected ApiKeyPermissionEntity() {
    }

    public String code() {
        return code;
    }

    public int status() {
        return status;
    }

    public boolean deprecated() {
        return deprecated;
    }

    /** Phoenix 只用启用且未废弃的目录项授予或计算权限。 */
    public boolean isActiveAndCurrent() {
        return status == 1 && !deprecated;
    }
}
