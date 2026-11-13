package app.keystone.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

/** 系统配置管理入口；具体持久化由 ORM 仓储负责。 */
@ApplicationScoped
public class SystemConfigRepository {
    @Inject SystemConfigOrmRepository ormConfigs;

    public List<SystemConfig> list() {
        try {
            return ormConfigs.listConfigs();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not list system configs", e);
        }
    }

    public SystemConfig find(String key) {
        try {
            return ormConfigs.findEnabled(key);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not find system config", e);
        }
    }

    public SystemConfig create(String key, String value, String description) {
        require(key, "key");
        require(value, "value");
        try {
            return ormConfigs.createConfig(key.trim(), value, description);
        } catch (RuntimeException e) {
            if (isUniqueConstraint(e)) throw new IllegalArgumentException("config key already exists", e);
            throw new IllegalStateException("Could not create system config", e);
        }
    }

    public SystemConfig update(String key, String value, String description, Boolean enabled) {
        try {
            return ormConfigs.updateConfig(key, value, description, enabled);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update system config", e);
        }
    }

    public void delete(String key) {
        try {
            ormConfigs.deleteConfig(key);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete system config", e);
        }
    }

    private static void require(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }

    private static boolean isUniqueConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("unique")) return true;
        }
        return false;
    }
}
