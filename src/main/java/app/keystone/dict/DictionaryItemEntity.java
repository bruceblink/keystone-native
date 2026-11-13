package app.keystone.dict;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.util.UUID;

/** 映射字典项记录及其所属字典类型。 */
@Entity
@Table(name = "sys_dict_item")
public class DictionaryItemEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "type_id", nullable = false)
    private DictionaryTypeEntity type;

    @Column(name = "item_value", nullable = false, length = 128)
    private String value;

    @Column(name = "item_label", nullable = false, length = 128)
    private String label;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    @Column(nullable = false)
    private boolean enabled;

    protected DictionaryItemEntity() {
    }

    DictionaryItemEntity(DictionaryTypeEntity type, String value, String label, int sortOrder) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.type = type;
        this.value = value;
        this.label = label;
        this.sortOrder = sortOrder;
        this.enabled = true;
    }

    String id() {
        return id.toString();
    }

    DictionaryTypeEntity type() {
        return type;
    }

    String value() {
        return value;
    }

    void update(String newLabel, Integer newSortOrder, Boolean newEnabled) {
        if (newLabel != null && !newLabel.isBlank()) label = newLabel.trim();
        if (newSortOrder != null) sortOrder = newSortOrder;
        if (newEnabled != null) enabled = newEnabled;
    }

    DictionaryItem toModel() {
        return new DictionaryItem(id.toString(), type.code(), value, label, sortOrder, enabled);
    }
}
