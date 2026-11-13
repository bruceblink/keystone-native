package app.keystone.dept;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Convert;
import app.keystone.identity.UuidBinaryConverter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.util.UUID;

/** 映射部门树节点，数据范围服务只读取父子关系。 */
@Entity
@Table(name = "sys_dept")
public class DepartmentEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "parent_id")
    @Convert(converter = UuidBinaryConverter.class)
    private String parentId;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    @Column(nullable = false)
    private boolean enabled;

    protected DepartmentEntity() {
    }

    String id() {
        return id == null ? null : id.toString();
    }

    DepartmentEntity(String code, String name, String parentId, int sortOrder) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.code = code;
        this.name = name;
        this.parentId = parentId;
        this.sortOrder = sortOrder;
        this.enabled = true;
    }

    void update(String newName, String newParentId, Integer newSortOrder, Boolean newEnabled) {
        if (newName != null && !newName.isBlank()) name = newName.trim();
        if (newParentId != null) parentId = newParentId;
        if (newSortOrder != null) sortOrder = newSortOrder;
        if (newEnabled != null) enabled = newEnabled;
    }

    Department toModel() {
        return new Department(id(), parentId, code, name, sortOrder, enabled);
    }
}
