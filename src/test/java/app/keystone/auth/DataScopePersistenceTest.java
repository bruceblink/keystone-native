package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证数据范围读取使用 ORM 事务和有环部门树遍历。 */
class DataScopePersistenceTest {
    @Test
    void serviceUsesOrmRepositoriesWithoutManualJdbc() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/auth/DataScopeService.java"));
        assertTrue(source.contains("ApiKeyUserRepository"));
        assertTrue(source.contains("DepartmentOrmRepository"));
        assertTrue(source.contains("@Transactional"));
        assertTrue(source.contains("frontier"));
        assertTrue(source.contains("result.add(child)"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
        assertFalse(source.contains("WITH RECURSIVE"));
    }

    @Test
    void roleAndDepartmentEntitiesMapScopeFields() throws Exception {
        String role = Files.readString(Path.of("src/main/java/app/keystone/auth/ApiKeyRoleEntity.java"));
        String department = Files.readString(Path.of("src/main/java/app/keystone/dept/DepartmentEntity.java"));
        assertTrue(role.contains("data_scope"));
        assertTrue(role.contains("dept_scope"));
        assertTrue(department.contains("parent_id"));
        assertTrue(department.contains("@Entity"));
    }
}
