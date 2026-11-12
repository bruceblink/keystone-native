package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MfaRecoveryCodeServiceTest {
    private final MfaRecoveryCodeService service = new MfaRecoveryCodeService("test-only-pepper");

    @Test
    void generatesFixedUniqueFormattedBatchAndHashesWithoutPlaintext() {
        var batch = service.generateBatch();
        assertEquals(MfaRecoveryCodeService.CODE_COUNT, batch.codes().size());
        assertEquals(MfaRecoveryCodeService.CODE_COUNT, new HashSet<>(batch.codes()).size());
        assertTrue(batch.codes().stream().allMatch(code -> code.matches("[0-9A-F]{4}(?:-[0-9A-F]{4}){7}")));

        String first = batch.codes().get(0);
        String hash = service.hash(first);
        assertEquals(hash, service.hash(first.toLowerCase()));
        assertTrue(service.matches(first, hash));
        assertTrue(service.matches(first.replace("-", ""), hash));
        assertFalse(service.matches(batch.codes().get(1), hash));
        assertNotEquals(first, hash);
    }

    @Test
    void rejectsMalformedCodesAndMissingPepper() {
        assertThrows(IllegalArgumentException.class, () -> service.hash("ABCD-1234"));
        assertThrows(IllegalArgumentException.class, () -> service.hash("ABCD-EFGH-1234-5678-90AB-CDEF-1234-5678"));
        assertFalse(service.matches("ABCD-1234", "not-a-hash"));

        var valid = service.generateBatch().codes();
        var duplicate = new java.util.ArrayList<>(valid);
        duplicate.set(1, duplicate.get(0));
        assertThrows(IllegalArgumentException.class, () -> new MfaRecoveryCodeService.RecoveryCodeBatch("batch", duplicate));

        var missing = new MfaRecoveryCodeService("");
        assertThrows(IllegalStateException.class, missing::generateBatch);
        assertThrows(IllegalStateException.class, () -> missing.hash("ABCD-1234-5678-90AB-CDEF-1234-5678-90AB"));
    }
}
