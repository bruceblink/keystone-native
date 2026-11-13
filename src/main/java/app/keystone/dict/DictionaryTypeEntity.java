package app.keystone.dict;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** 映射字典类型记录。 */
@Entity
@Table(name = "sys_dict_type")
public class DictionaryTypeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 64)
    private String code;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false)
    private boolean enabled;

    protected DictionaryTypeEntity() {
    }

    DictionaryTypeEntity(String code, String name) {
        this.code = code;
        this.name = name;
        this.enabled = true;
    }

    long id() {
        return id;
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
        return new DictionaryType(id, code, name, enabled);
    }
}
