package app.keystone.config;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** 映射系统配置记录，表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_config")
public class SystemConfigEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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
        return new SystemConfig(id, key, value, description, enabled, updatedAt);
    }
}
