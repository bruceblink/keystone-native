package app.keystone.dict;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** 使用 Panache 管理字典项。 */
@ApplicationScoped
public class DictionaryItemOrmRepository implements PanacheRepositoryBase<DictionaryItemEntity, java.util.UUID> {
    @jakarta.inject.Inject DictionaryTypeOrmRepository types;

    @Transactional
    public List<DictionaryItem> listItems(String typeCode) {
        return listItems(typeCode, null);
    }

    /** 按值或显示名称过滤字典条目，未提供 keyword 时保持原数组查询行为。 */
    @Transactional
    public List<DictionaryItem> listItems(String typeCode, String keyword) {
        return itemQuery(typeCode, keyword)
                .list().stream().map(DictionaryItemEntity::toModel).toList();
    }

    /** 使用数据库分页读取指定字典类型的条目，避免管理页面一次加载全部数据。 */
    @Transactional
    public DictionaryRepository.Page listItems(String typeCode, int page, int size) {
        return listItems(typeCode, page, size, null);
    }

    /** 使用数据库分页读取筛选后的条目，并按筛选结果计算 total。 */
    @Transactional
    public DictionaryRepository.Page listItems(String typeCode, int page, int size, String keyword) {
        int safePage = Math.max(1, page);
        int safeSize = Math.min(100, Math.max(1, size));
        PanacheQuery<DictionaryItemEntity> query = itemQuery(typeCode, keyword);
        long total = query.count();
        List<DictionaryItem> items = query.page(io.quarkus.panache.common.Page.of(safePage - 1, safeSize))
                .list().stream().map(DictionaryItemEntity::toModel).toList();
        return new DictionaryRepository.Page(items, safePage, safeSize, total);
    }

    private PanacheQuery<DictionaryItemEntity> itemQuery(String typeCode, String keyword) {
        List<Object> parameters = new ArrayList<>();
        parameters.add(typeCode);
        String query = "type.code = ?1 and type.enabled = true";
        if (keyword != null && !keyword.isBlank()) {
            parameters.add("%" + keyword.trim().toLowerCase(Locale.ROOT) + "%");
            query += " and (lower(value) like ?2 or lower(label) like ?2)";
        }
        return find(query + " order by sortOrder, id", parameters.toArray());
    }

    @Transactional
    public DictionaryItem createItem(String typeCode, String value, String label, int sortOrder) {
        return createItem(typeCode, value, label, sortOrder, null);
    }

    /** 在 ORM 事务中保存字典项的初始启用状态。 */
    @Transactional
    public DictionaryItem createItem(String typeCode, String value, String label, int sortOrder, Boolean enabled) {
        DictionaryTypeEntity type = types.findEnabledByCode(typeCode);
        if (type == null) throw new java.util.NoSuchElementException("dictionary type not found");
        var item = new DictionaryItemEntity(type, value.trim(), label.trim(), sortOrder, enabled);
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
