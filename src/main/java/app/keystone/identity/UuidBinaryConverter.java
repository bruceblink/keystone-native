package app.keystone.identity;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * 在 JPA 属性和 MySQL BINARY(16) 列之间转换 UUID。
 * 查询条件应绑定转换后的 16 字节参数，以保留二进制列索引。
 */
@Converter(autoApply = false)
public final class UuidBinaryConverter implements AttributeConverter<String, byte[]> {
    @Override
    public byte[] convertToDatabaseColumn(String attribute) {
        return attribute == null ? null : UuidValues.toBytes(attribute);
    }

    @Override
    public String convertToEntityAttribute(byte[] dbData) {
        return dbData == null ? null : UuidValues.fromBytes(dbData);
    }
}
