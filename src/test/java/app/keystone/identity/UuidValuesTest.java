package app.keystone.identity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.Test;

class UuidValuesTest {
    @Test
    void generatesCanonicalUuidV7WithTimestampAndVersion() {
        String value = UuidValues.v7();
        UUID uuid = UUID.fromString(value);

        assertEquals(value, value.toLowerCase());
        assertEquals(7, uuid.version());
        assertEquals(2, uuid.variant());
        assertTrue(value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    @Test
    void generatesStablePermissionUuidV5() {
        String first = UuidValues.permissionId("user:read");
        String second = UuidValues.permissionId("user:read");
        UUID uuid = UUID.fromString(first);

        assertEquals(first, second);
        assertEquals(5, uuid.version());
        assertEquals(2, uuid.variant());
        assertEquals("950c8856-7230-5a63-937f-472185c3a8c4", first);
    }

    @Test
    void convertsCanonicalUuidToAndFromBinary16() {
        String value = "018f0f2a-6e28-7abc-8def-0123456789ab";

        byte[] encoded = UuidValues.toBytes(value);

        assertEquals(value, UuidValues.fromBytes(encoded));
        assertArrayEquals(encoded, new UuidBinaryConverter().convertToDatabaseColumn(value));
        assertEquals(value, new UuidBinaryConverter().convertToEntityAttribute(encoded));
    }

    @Test
    void rejectsNonCanonicalUuidAndWrongBinaryLength() {
        assertThrows(IllegalArgumentException.class,
                () -> UuidValues.requireCanonical("018f0f2a-6e28-7abc-8DEF-0123456789ab"));
        assertThrows(IllegalArgumentException.class, () -> UuidValues.fromBytes(new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> UuidValues.permissionId("system:user:read"));
    }
}
