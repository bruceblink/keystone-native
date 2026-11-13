package app.keystone.config;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

/** 使用 Panache 管理系统配置记录。 */
@ApplicationScoped
public class SystemConfigOrmRepository implements PanacheRepositoryBase<SystemConfigEntity, Long> {
    @Transactional
    public List<SystemConfig> listConfigs() {
        return find("order by key").list().stream().map(SystemConfigEntity::toModel).toList();
    }

    @Transactional
    public SystemConfig findEnabled(String key) {
        SystemConfigEntity config = find("key = ?1 and enabled = true", key).firstResult();
        if (config == null) throw new java.util.NoSuchElementException("config not found");
        return config.toModel();
    }

    @Transactional
    public SystemConfig createConfig(String key, String value, String description) {
        var config = new SystemConfigEntity(key, value, description);
        persistAndFlush(config);
        return config.toModel();
    }

    @Transactional
    public SystemConfig updateConfig(String key, String value, String description, Boolean enabled) {
        SystemConfigEntity config = find("key", key).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (config == null) throw new java.util.NoSuchElementException("config not found");
        config.update(value, description, enabled);
        return config.toModel();
    }

    @Transactional
    public void deleteConfig(String key) {
        SystemConfigEntity config = find("key", key).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (config == null) throw new java.util.NoSuchElementException("config not found");
        delete(config);
    }
}
