package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 核验当前 MySQL 用户名唯一索引的名称及驱动错误元数据。 */
@QuarkusTest
class UsernameUniqueConstraintTest {
    @Inject DataSource dataSource;

    @Test
    void duplicateUsernameUsesMysqlDuplicateKeyCodeAndUsernameIndex() throws Exception {
        String indexName;
        try (var connection = dataSource.getConnection();
             var query = connection.prepareStatement("SELECT index_name FROM information_schema.statistics " +
                     "WHERE table_schema = DATABASE() AND table_name = 'sys_user' " +
                     "AND column_name = 'username' AND non_unique = 0")) {
            try (var rows = query.executeQuery()) {
                assertTrue(rows.next());
                indexName = rows.getString(1);
            }
        }

        SQLException duplicate = null;
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.executeUpdate("INSERT INTO sys_user (id, username, password_hash, display_name) " +
                    "VALUES (UNHEX(REPLACE(UUID(), '-', '')), 'admin', 'test-only', 'duplicate')");
        } catch (SQLException error) {
            duplicate = error;
        }

        assertNotNull(duplicate);
        assertEquals("username", indexName);
        assertEquals("23000", duplicate.getSQLState());
        assertEquals(1062, duplicate.getErrorCode());
        assertTrue(duplicate.getMessage().contains(indexName));
    }
}
