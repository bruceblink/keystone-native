package app.keystone.dict;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.util.UUID;

/** 映射字典类型记录。 */
@Entity
@Table(name = "sys_dict_type")
public class DictionaryTypeEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false)
    private boolean enabled;

    protected DictionaryTypeEntity() {
    }

    DictionaryTypeEntity(String code, String name) {
        this.id = UUID.fromString(app.keystone.identity.UuidValues.v7());
        this.code = code;
        this.name = name;
        this.enabled = true;
    }

    String id() {
        return id.toString();
    }

    String code() {
        return code;
    }

    boolean enabled() {
        return enabled;
    }

    void update(String newName, Boolean newEnabled) {
        if (newName != null && !newName.isBlank()) name = newName.trim();
        if (newEnabled != null) enabled = newEnabled;
    }

    DictionaryType toModel() {
        return new DictionaryType(id.toString(), code, name, enabled);
    }
}
