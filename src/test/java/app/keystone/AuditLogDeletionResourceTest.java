package app.keystone;

import app.keystone.identity.UuidValues;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 通过真实 HTTP 和 MySQL 验证两类审计日志的批量删除事务边界。 */
@QuarkusTest
class AuditLogDeletionResourceTest extends AuthTestFixture {
    @Inject DataSource dataSource;

    @Test
    void mixedOperationLogDeletionRollsBackWhenOneIdIsMissing() throws Exception {
        String token = login();
        String existing = UuidValues.v7();
        String missing = UuidValues.v7();
        insertOperationLog(existing);
        try {
            given().auth().oauth2(token).when().delete("/v1/operation-logs?ids=" + existing + "," + missing)
                    .then().statusCode(404).body("error.code", is("validation_failed"));
            assertTrue(exists("sys_operation_log", existing));
        } finally {
            delete("sys_operation_log", existing);
        }
    }

    @Test
    void mixedLoginLogDeletionRollsBackWhenOneIdIsMissing() throws Exception {
        String token = login();
        String existing = UuidValues.v7();
        String missing = UuidValues.v7();
        insertLoginLog(existing);
        try {
            given().auth().oauth2(token).when().delete("/v1/login-logs?ids=" + existing + "," + missing)
                    .then().statusCode(404).body("error.code", is("validation_failed"));
            assertTrue(exists("sys_login_log", existing));
        } finally {
            delete("sys_login_log", existing);
        }
    }

    private String login() {
        return given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }

    private void insertLoginLog(String id) throws Exception {
        execute("INSERT INTO sys_login_log(id, username, status, message) VALUES (UUID_TO_BIN(?, 0), 'mixed-delete', 'SUCCESS', 'test')", id);
    }

    private void insertOperationLog(String id) throws Exception {
        execute("INSERT INTO sys_operation_log(id, actor_username, action, resource, detail) VALUES (UUID_TO_BIN(?, 0), 'mixed-delete', 'TEST', 'audit', 'test')", id);
    }

    private boolean exists(String table, String id) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM " + table + " WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, id);
            try (var result = statement.executeQuery()) {
                return result.next() && result.getInt(1) == 1;
            }
        }
    }

    private void delete(String table, String id) throws Exception {
        execute("DELETE FROM " + table + " WHERE id = UUID_TO_BIN(?, 0)", id);
    }

    private void execute(String sql, String id) throws Exception {
        try (Connection connection = dataSource.getConnection(); PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, id);
            statement.executeUpdate();
        }
    }
}
