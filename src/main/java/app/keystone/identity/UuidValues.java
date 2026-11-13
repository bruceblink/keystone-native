package app.keystone.identity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * 提供主键 UUID 的统一生成、校验和二进制边界转换。
 * UUIDv7 用于新业务实体，UUIDv5 只用于固定名称的稳定目录标识。
 */
public final class UuidValues {
    /** 跨项目固定命名空间，用于生成权限目录的 UUIDv5。 */
    public static final UUID PERMISSION_NAMESPACE =
            UUID.fromString("eb754ae2-49de-5e5f-87ef-1fa5eded86d8");

    private static final Pattern CANONICAL_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidValues() {
    }

    /** 生成规范小写连字符 UUIDv7。随机源失败时直接抛出异常，不回退到其他格式。 */
    public static String v7() {
        return v7Uuid().toString();
    }

    /** 生成 UUIDv7 对象，时间戳位于高 48 位以保持数据库索引顺序。 */
    public static UUID v7Uuid() {
        long timestamp = System.currentTimeMillis();
        if ((timestamp & ~0xFFFFFFFFFFFFL) != 0) {
            throw new IllegalStateException("UUIDv7 timestamp exceeds 48 bits");
        }
        int randomA = RANDOM.nextInt(1 << 12);
        long mostSignificantBits = (timestamp << 16) | 0x7000L | randomA;
        long leastSignificantBits = RANDOM.nextLong() & 0x3FFFFFFFFFFFFFFFL;
        leastSignificantBits |= 0x8000000000000000L;
        return new UUID(mostSignificantBits, leastSignificantBits);
    }

    /** 根据固定命名空间和名称生成稳定的 UUIDv5。 */
    public static String v5(UUID namespace, String name) {
        Objects.requireNonNull(namespace, "namespace");
        Objects.requireNonNull(name, "name");
        byte[] namespaceBytes = toBytes(namespace);
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] digest = sha1(namespaceBytes, nameBytes);
        digest[6] = (byte) ((digest[6] & 0x0F) | 0x50);
        digest[8] = (byte) ((digest[8] & 0x3F) | 0x80);
        return uuidFromBytes(digest).toString();
    }

    /** 生成权限目录的稳定 UUIDv5，名称格式固定为 permission:<resource:action>。 */
    public static String permissionId(String permission) {
        String canonicalPermission = requirePermission(permission);
        return v5(PERMISSION_NAMESPACE, "permission:" + canonicalPermission);
    }

    /** 校验并返回规范小写连字符 UUID 字符串。 */
    public static String requireCanonical(String value) {
        Objects.requireNonNull(value, "uuid");
        if (!CANONICAL_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("uuid must use lowercase canonical format");
        }
        return value;
    }

    /** 将已经校验的 UUID 字符串转换为 ORM 使用的 UUID 值。 */
    public static UUID parse(String value) {
        return UUID.fromString(requireCanonical(value));
    }

    /** 将规范 UUID 字符串转换为 MySQL BINARY(16) 的 16 字节值。 */
    public static byte[] toBytes(String value) {
        return toBytes(UUID.fromString(requireCanonical(value)));
    }

    /** 将 UUID 对象编码为 MySQL BINARY(16) 的网络字节序。 */
    public static byte[] toBytes(UUID value) {
        Objects.requireNonNull(value, "uuid");
        return ByteBuffer.allocate(16)
                .putLong(value.getMostSignificantBits())
                .putLong(value.getLeastSignificantBits())
                .array();
    }

    /** 将 MySQL BINARY(16) 的 16 字节值转换为规范小写 UUID 字符串。 */
    public static String fromBytes(byte[] value) {
        return fromBytesToUuid(value).toString();
    }

    /** 将 MySQL BINARY(16) 的 16 字节值转换为 UUID 对象。 */
    public static UUID fromBytesToUuid(byte[] value) {
        Objects.requireNonNull(value, "uuid bytes");
        if (value.length != 16) {
            throw new IllegalArgumentException("uuid bytes must contain exactly 16 bytes");
        }
        ByteBuffer buffer = ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static byte[] sha1(byte[] namespace, byte[] name) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(namespace);
            digest.update(name);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is required for UUIDv5", e);
        }
    }

    private static UUID uuidFromBytes(byte[] value) {
        byte[] firstSixteen = new byte[16];
        System.arraycopy(value, 0, firstSixteen, 0, firstSixteen.length);
        return fromBytesToUuid(firstSixteen);
    }

    private static String requirePermission(String permission) {
        Objects.requireNonNull(permission, "permission");
        if (!permission.matches("[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*")) {
            throw new IllegalArgumentException("permission must use resource:action format");
        }
        return permission;
    }
}
