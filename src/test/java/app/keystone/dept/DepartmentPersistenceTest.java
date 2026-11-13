package app.keystone.dept;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证部门管理入口使用 ORM，不重新引入 JDBC。 */
class DepartmentPersistenceTest {
    @Test
    void departmentRepositoryDelegatesToOrm() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/dept/DepartmentRepository.java"));
        assertTrue(source.contains("DepartmentOrmRepository"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }

    @Test
    void departmentOrmRepositoryUsesTransactionsAndLocks() throws Exception {
        String source = Files.readString(Path.of("src/main/java/app/keystone/dept/DepartmentOrmRepository.java"));
        assertTrue(source.contains("@Transactional"));
        assertTrue(source.contains("PESSIMISTIC_WRITE"));
        assertTrue(source.contains("parentId"));
        assertFalse(source.contains("DataSource"));
        assertFalse(source.contains("prepareStatement"));
    }
}
