package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataScopePolicyTest {
    @Test
    void exposesTheSharedScopeDirectoryAndResourceMatrix() {
        assertTrue(DataScopePolicy.registered("tenant"));
        assertTrue(DataScopePolicy.supported("user", "TENANT"));
        assertTrue(DataScopePolicy.supported("owned", "MEMBER"));
        assertFalse(DataScopePolicy.supported("user", "OWNER"));
        assertFalse(DataScopePolicy.registered("UNKNOWN"));
    }
}
