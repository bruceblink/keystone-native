package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** 映射 API Key 签发所需的权限记录。 */
@Entity
@Table(name = "sys_permission")
public class ApiKeyPermissionEntity {
    @Id
    private Long id;

    @Column(nullable = false, length = 128)
    private String code;

    protected ApiKeyPermissionEntity() {
    }

    String code() {
        return code;
    }
}
