package app.keystone.dict;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;

/** 使用 Panache 管理字典项。 */
@ApplicationScoped
public class DictionaryItemOrmRepository implements PanacheRepositoryBase<DictionaryItemEntity, java.util.UUID> {
    @jakarta.inject.Inject DictionaryTypeOrmRepository types;

    @Transactional
    public List<DictionaryItem> listItems(String typeCode) {
        return find("type.code = ?1 and type.enabled = true order by sortOrder, id", typeCode)
                .list().stream().map(DictionaryItemEntity::toModel).toList();
    }

    @Transactional
    public DictionaryItem createItem(String typeCode, String value, String label, int sortOrder) {
        DictionaryTypeEntity type = types.findEnabledByCode(typeCode);
        if (type == null) throw new java.util.NoSuchElementException("dictionary type not found");
        var item = new DictionaryItemEntity(type, value.trim(), label.trim(), sortOrder);
        persistAndFlush(item);
        return item.toModel();
    }

    @Transactional
    public DictionaryItem updateItem(String id, String label, Integer sortOrder, Boolean enabled) {
        DictionaryItemEntity item = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (item == null) throw new java.util.NoSuchElementException("dictionary item not found");
        item.update(label, sortOrder, enabled);
        return item.toModel();
    }

    @Transactional
    public void deleteItem(String id) {
        DictionaryItemEntity item = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (item == null) throw new java.util.NoSuchElementException("dictionary item not found");
        delete(item);
    }
}
