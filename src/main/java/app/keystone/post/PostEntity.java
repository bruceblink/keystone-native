package app.keystone.post;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.util.UUID;

/** 映射岗位基础信息；数据库表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_post")
public class PostEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    @Column(nullable = false)
    private boolean enabled;

    protected PostEntity() {
    }

    PostEntity(String code, String name, int sortOrder) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.code = code.trim();
        this.name = name.trim();
        this.sortOrder = sortOrder;
        this.enabled = true;
    }

    void update(String newName, Integer newSortOrder, Boolean newEnabled) {
        if (newName != null && !newName.isBlank()) name = newName.trim();
        if (newSortOrder != null) sortOrder = newSortOrder;
        if (newEnabled != null) enabled = newEnabled;
    }

    Post toModel() {
        return new Post(id == null ? null : id.toString(), code, name, sortOrder, enabled);
    }
}
