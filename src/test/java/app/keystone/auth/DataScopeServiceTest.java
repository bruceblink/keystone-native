package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataScopeServiceTest {
    @Test
    void selfScopeOnlyAllowsTheUsersOwnDepartment() {
        var scope = new DataScopeService.Scope(false, true, Set.of(), 7L);

        assertTrue(scope.allowsDepartment(7L));
        assertFalse(scope.allowsDepartment(8L));
    }

    @Test
    void customDepartmentScopeAllowsOnlyConfiguredDepartments() {
        var scope = new DataScopeService.Scope(false, false, Set.of(7L, 9L), null);

        assertTrue(scope.allowsDepartment(7L));
        assertTrue(scope.allowsDepartment(9L));
        assertFalse(scope.allowsDepartment(8L));
    }

    @Test
    void restrictedScopeCanCreateOnlyUnderAnAllowedDepartment() {
        var scope = new DataScopeService.Scope(false, true, Set.of(), 7L);

        assertTrue(scope.allowsDepartmentCreation(7L));
        assertFalse(scope.allowsDepartmentCreation(8L));
        assertFalse(scope.allowsDepartmentCreation(null));
    }

    @Test
    void departmentUpdateRequiresTargetAndNewParentWithinScope() {
        var scope = new DataScopeService.Scope(false, false, Set.of(7L, 9L), null);

        assertTrue(scope.allowsDepartmentUpdate(7L, null));
        assertTrue(scope.allowsDepartmentUpdate(7L, 9L));
        assertFalse(scope.allowsDepartmentUpdate(8L, 7L));
        assertFalse(scope.allowsDepartmentUpdate(7L, 8L));
    }
}
