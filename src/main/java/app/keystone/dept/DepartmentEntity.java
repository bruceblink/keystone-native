package app.keystone.dept;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** 映射部门树节点，数据范围服务只读取父子关系。 */
@Entity
@Table(name = "sys_dept")
public class DepartmentEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "parent_id")
    private Long parentId;

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

    Long id() {
        return id;
    }

    DepartmentEntity(String code, String name, Long parentId, int sortOrder) {
        this.code = code;
        this.name = name;
        this.parentId = parentId;
        this.sortOrder = sortOrder;
        this.enabled = true;
    }

    void update(String newName, Long newParentId, Integer newSortOrder, Boolean newEnabled) {
        if (newName != null && !newName.isBlank()) name = newName.trim();
        if (newParentId != null) parentId = newParentId;
        if (newSortOrder != null) sortOrder = newSortOrder;
        if (newEnabled != null) enabled = newEnabled;
    }

    Department toModel() {
        return new Department(id, parentId, code, name, sortOrder, enabled);
    }
}
