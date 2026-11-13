package app.keystone.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** ORM 映射登录日志；数据库表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_login_log")
public class LoginLogEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 128)
    private String username;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(length = 255)
    private String message;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "login_at", nullable = false, insertable = false, updatable = false)
    private Instant loginAt;

    protected LoginLogEntity() {
    }

    LoginLogEntity(String username, String status, String ipAddress, String message, String userAgent) {
        this.id = java.util.UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.username = username;
        this.status = status;
        this.ipAddress = ipAddress;
        this.message = message;
        this.userAgent = userAgent;
    }

    LoginLog toModel() {
        return new LoginLog(id == null ? null : id.toString(), username, status, ipAddress, message, userAgent, loginAt);
    }
}
