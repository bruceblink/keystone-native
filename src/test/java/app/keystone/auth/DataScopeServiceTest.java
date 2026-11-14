package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataScopeServiceTest {
    private static final String DEPT_7 = "00000000-0000-7000-8000-000000000007";
    private static final String DEPT_8 = "00000000-0000-7000-8000-000000000008";
    private static final String DEPT_9 = "00000000-0000-7000-8000-000000000009";
    @Test
    void selfScopeOnlyAllowsTheUsersOwnDepartment() {
        var scope = new DataScopeService.Scope(false, true, Set.of(), DEPT_7);

        assertTrue(scope.allowsDepartment(DEPT_7));
        assertFalse(scope.allowsDepartment(DEPT_8));
    }

    @Test
    void customDepartmentScopeAllowsOnlyConfiguredDepartments() {
        var scope = new DataScopeService.Scope(false, false, Set.of(DEPT_7, DEPT_9), null);

        assertTrue(scope.allowsDepartment(DEPT_7));
        assertTrue(scope.allowsDepartment(DEPT_9));
        assertFalse(scope.allowsDepartment(DEPT_8));
    }

    @Test
    void ownerScopeIsKeptSeparateFromSelfScope() {
        var scope = new DataScopeService.Scope(false, false, true, Set.of(), null);

        assertTrue(scope.owner());
        assertFalse(scope.self());
        assertFalse(scope.isEmpty());
    }

    @Test
    void restrictedScopeCanCreateOnlyUnderAnAllowedDepartment() {
        var scope = new DataScopeService.Scope(false, true, Set.of(), DEPT_7);

        assertTrue(scope.allowsDepartmentCreation(DEPT_7));
        assertFalse(scope.allowsDepartmentCreation(DEPT_8));
        assertFalse(scope.allowsDepartmentCreation(null));
    }

    @Test
    void departmentUpdateRequiresTargetAndNewParentWithinScope() {
        var scope = new DataScopeService.Scope(false, false, Set.of(DEPT_7, DEPT_9), null);

        assertTrue(scope.allowsDepartmentUpdate(DEPT_7, null));
        assertTrue(scope.allowsDepartmentUpdate(DEPT_7, DEPT_9));
        assertFalse(scope.allowsDepartmentUpdate(DEPT_8, DEPT_7));
        assertFalse(scope.allowsDepartmentUpdate(DEPT_7, DEPT_8));
    }
}
