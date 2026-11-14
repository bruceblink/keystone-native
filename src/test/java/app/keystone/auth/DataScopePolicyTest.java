package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    @Test
    void requiresGlobalScopeForResourcesWithoutAnOwnerRelation() {
        var role = DataScopePolicy.rule("role");
        var file = DataScopePolicy.rule("file");

        assertNotNull(role);
        assertEquals(DataScopePolicy.Enforcement.ALL_OR_TENANT, role.enforcement());
        assertEquals(DataScopePolicy.Enforcement.ALL_OR_TENANT, file.enforcement());
        assertFalse(DataScopePolicy.allows(role, false, true, false));
        assertTrue(DataScopePolicy.allows(role, true, false, false));
        assertFalse(DataScopePolicy.allows(file, false, true, false));
    }

    @Test
    void separatesSelfResourcesFromOwnerResources() {
        var apiKey = DataScopePolicy.rule("api-key");
        var notice = DataScopePolicy.rule("notice");

        assertNotNull(apiKey);
        assertNotNull(notice);
        assertEquals(DataScopePolicy.Enforcement.OWNER_BOUND, apiKey.enforcement());
        assertEquals(DataScopePolicy.Enforcement.OWNER_BOUND, notice.enforcement());
        assertTrue(DataScopePolicy.supported("notice", "OWNER"));
        assertFalse(DataScopePolicy.supported("notice", "SELF"));
        assertTrue(DataScopePolicy.allows(apiKey, false, true, false));
        assertFalse(DataScopePolicy.allows(notice, false, true, false));
        assertTrue(DataScopePolicy.allows(notice, false, false, true));
        assertFalse(DataScopePolicy.allows(apiKey, false, false, false));
    }

    @Test
    void keepsQueryFilteredResourcesAvailableForRepositoryChecks() {
        var user = DataScopePolicy.rule("user");

        assertNotNull(user);
        assertEquals(DataScopePolicy.Enforcement.QUERY_FILTERED, user.enforcement());
        assertTrue(DataScopePolicy.allows(user, false, false, false));
    }
}
