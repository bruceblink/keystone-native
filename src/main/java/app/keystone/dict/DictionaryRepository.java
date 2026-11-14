package app.keystone.dict;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

/** 字典管理入口；具体持久化由 ORM 仓储负责。 */
@ApplicationScoped
public class DictionaryRepository {
    @Inject DictionaryTypeOrmRepository typesRepository;
    @Inject DictionaryItemOrmRepository itemsRepository;
    @Inject AuthorizationService authorization;

    public List<DictionaryType> types(AuthorizationContext context) {
        authorization.require(context, "dictionary:read", "dictionary");
        try {
            return typesRepository.listTypes();
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not list dictionary types", e);
        }
    }

    public List<DictionaryItem> items(AuthorizationContext context, String typeCode) {
        authorization.require(context, "dictionary:read", "dictionary");
        try {
            return itemsRepository.listItems(typeCode);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not list dictionary items", e);
        }
    }

    public DictionaryType createType(AuthorizationContext context, String code, String name) {
        authorization.require(context, "dictionary:create", "dictionary");
        require(code, "code");
        require(name, "name");
        try {
            return typesRepository.createType(code, name);
        } catch (RuntimeException e) {
            if (isUniqueConstraint(e)) throw new IllegalArgumentException("dictionary type code already exists", e);
            throw new IllegalStateException("Could not create dictionary type", e);
        }
    }

    public DictionaryItem createItem(AuthorizationContext context, String typeCode, String value, String label, Integer sortOrder) {
        authorization.require(context, "dictionary:create", "dictionary");
        require(typeCode, "typeCode");
        require(value, "value");
        require(label, "label");
        try {
            return itemsRepository.createItem(typeCode, value, label, sortOrder == null ? 0 : sortOrder);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isUniqueConstraint(e)) throw new IllegalArgumentException("dictionary item value already exists", e);
            throw new IllegalStateException("Could not create dictionary item", e);
        }
    }

    public DictionaryType updateType(AuthorizationContext context, String code, String name, Boolean enabled) {
        authorization.require(context, "dictionary:update", "dictionary");
        try {
            return typesRepository.updateType(code, name, enabled);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update dictionary type", e);
        }
    }

    public DictionaryItem updateItem(AuthorizationContext context, String id, String label, Integer sortOrder, Boolean enabled) {
        authorization.require(context, "dictionary:update", "dictionary");
        try {
            return itemsRepository.updateItem(id, label, sortOrder, enabled);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not update dictionary item", e);
        }
    }

    public void deleteType(AuthorizationContext context, String code) {
        authorization.require(context, "dictionary:delete", "dictionary");
        try {
            typesRepository.deleteType(code);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete dictionary type", e);
        }
    }

    public void deleteItem(AuthorizationContext context, String id) {
        authorization.require(context, "dictionary:delete", "dictionary");
        try {
            itemsRepository.deleteItem(id);
        } catch (java.util.NoSuchElementException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not delete dictionary item", e);
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
