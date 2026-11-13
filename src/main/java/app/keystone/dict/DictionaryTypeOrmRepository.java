package app.keystone.dict;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

/** 使用 Panache 管理字典类型。 */
@ApplicationScoped
public class DictionaryTypeOrmRepository implements PanacheRepositoryBase<DictionaryTypeEntity, Long> {
    @Transactional
    public List<DictionaryType> listTypes() {
        return find("order by code").list().stream().map(DictionaryTypeEntity::toModel).toList();
    }

    @Transactional
    public DictionaryType createType(String code, String name) {
        var type = new DictionaryTypeEntity(code.trim(), name.trim());
        persistAndFlush(type);
        return type.toModel();
    }

    @Transactional
    public DictionaryType updateType(String code, String name, Boolean enabled) {
        DictionaryTypeEntity type = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (type == null) throw new java.util.NoSuchElementException("dictionary type not found");
        type.update(name, enabled);
        return type.toModel();
    }

    @Transactional
    public void deleteType(String code) {
        DictionaryTypeEntity type = find("code", code).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (type == null) throw new java.util.NoSuchElementException("dictionary type not found");
        delete(type);
    }

    DictionaryTypeEntity findEnabledByCode(String code) {
        return find("code = ?1 and enabled = true", code).firstResult();
    }
}
