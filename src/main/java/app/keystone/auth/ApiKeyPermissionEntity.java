package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

/** 映射 API Key 签发所需的权限记录。 */
@Entity
@Table(name = "sys_permission")
public class ApiKeyPermissionEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "id", columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 128)
    private String code;

    protected ApiKeyPermissionEntity() {
    }

    String code() {
        return code;
    }
}
