package app.keystone.config;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/** 映射系统配置记录，表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_config")
public class SystemConfigEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "config_key", nullable = false, length = 128)
    private String key;

    @Column(name = "config_value", nullable = false, length = 2000)
    private String value;

    @Column(length = 255)
    private String description;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected SystemConfigEntity() {
    }

    SystemConfigEntity(String key, String value, String description) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.key = key;
        this.value = value;
        this.description = description;
        this.enabled = true;
    }

    void update(String newValue, String newDescription, Boolean newEnabled) {
        if (newValue != null) value = newValue;
        if (newDescription != null) description = newDescription;
        if (newEnabled != null) enabled = newEnabled;
    }

    SystemConfig toModel() {
        return new SystemConfig(id.toString(), key, value, description, enabled, updatedAt);
    }
}
