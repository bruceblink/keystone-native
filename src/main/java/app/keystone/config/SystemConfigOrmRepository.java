package app.keystone.config;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.quarkus.panache.common.Page;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.ArrayList;
import java.util.List;

/** 使用 Panache 管理系统配置记录。 */
@ApplicationScoped
public class SystemConfigOrmRepository implements PanacheRepositoryBase<SystemConfigEntity, java.util.UUID> {
    @Transactional
    public List<SystemConfig> listConfigs() {
        return listConfigs(null, null);
    }

    @Transactional
    public List<SystemConfig> listConfigs(String keyword, String configKey) {
        return configQuery(keyword, configKey).list().stream().map(SystemConfigEntity::toModel).toList();
    }

    /** 使用数据库分页读取配置，避免管理页面一次加载全部记录。 */
    @Transactional
    public SystemConfigRepository.Page listConfigs(int page, int size, String keyword, String configKey) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        PanacheQuery<SystemConfigEntity> query = configQuery(keyword, configKey);
        long total = query.count();
        List<SystemConfig> items = query.page(Page.of(safePage - 1, safeSize)).list().stream()
                .map(SystemConfigEntity::toModel)
                .toList();
        return new SystemConfigRepository.Page(items, safePage, safeSize, total);
    }

    private PanacheQuery<SystemConfigEntity> configQuery(String keyword, String configKey) {
        List<String> conditions = new ArrayList<>();
        List<Object> parameters = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            conditions.add("(key like ?1 or description like ?1)");
            parameters.add("%" + keyword.trim() + "%");
        }
        if (configKey != null && !configKey.isBlank()) {
            int index = parameters.size() + 1;
            conditions.add("key like ?" + index);
            parameters.add("%" + configKey.trim() + "%");
        }
        String query = (conditions.isEmpty() ? "" : "where " + String.join(" and ", conditions)) + " order by key";
        return parameters.isEmpty()
                ? find(query)
                : find(query, parameters.toArray());
    }

    @Transactional
    public SystemConfig findEnabled(String key) {
        SystemConfigEntity config = find("key = ?1 and enabled = true", key).firstResult();
        if (config == null) throw new java.util.NoSuchElementException("config not found");
        return config.toModel();
    }

    @Transactional
    public SystemConfig createConfig(String key, String value, String description) {
        return createConfig(key, value, description, null);
    }

    /** 在 ORM 事务中保存系统配置的初始启用状态。 */
    @Transactional
    public SystemConfig createConfig(String key, String value, String description, Boolean enabled) {
        var config = new SystemConfigEntity(key, value, description, enabled);
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
