package app.keystone;

import app.keystone.identity.UuidValues;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 和 MySQL 验证用户批量删除的范围失败会整体回滚。 */
@QuarkusTest
class UserBatchDeletionResourceHttpTest {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";

    @Inject DataSource dataSource;
    private String roleId;
    private String ownerId;
    private String outsideId;
    private String ownerName;
    private String ownerToken;
    private String adminToken;

    @BeforeEach
    void createSelfScopedSubjects() throws Exception {
        roleId = UuidValues.v7();
        ownerId = UuidValues.v7();
        outsideId = UuidValues.v7();
        ownerName = "batch_delete_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        try (Connection connection = dataSource.getConnection()) {
            clearLoginRateLimits(connection);
            insertRole(connection);
            insertUsers(connection);
            insertPermissions(connection);
            insertUserRole(connection);
        }
        ownerToken = login(ownerName);
        adminToken = login("admin");
    }

    @AfterEach
    void removeSubjects() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            deleteUser(connection, ownerId);
            deleteUser(connection, outsideId);
            deleteRole(connection, roleId);
        }
    }

    @Test
    void outOfScopeBatchDeleteRollsBackVisibleTarget() {
        given().auth().oauth2(ownerToken)
                .when().delete("/v1/users?ids=" + ownerId + "," + outsideId)
                .then().statusCode(403)
                .body("error.code", is("data_scope_denied"));

        given().auth().oauth2(ownerToken)
                .when().delete("/v1/users?ids=" + ownerId + "," + UUID.randomUUID())
                .then().statusCode(404);

        given().auth().oauth2(adminToken).when().get("/v1/users/" + ownerId)
                .then().statusCode(200).body("data.id", is(ownerId));
        given().auth().oauth2(adminToken).when().delete("/v1/users?ids=" + ownerId)
                .then().statusCode(200).body("data.deleted", is(1));
        given().auth().oauth2(adminToken).when().get("/v1/users/" + ownerId)
                .then().statusCode(404);
    }

    private String login(String username) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }

    private void insertRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'SELF')")) {
            statement.setString(1, roleId);
            statement.setString(2, "BATCH_DELETE_" + roleId.substring(0, 8));
            statement.setString(3, "Batch delete self role");
            statement.executeUpdate();
        }
    }

    private void insertUsers(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_user (id, username, password_hash, display_name, enabled, must_change_password, failed_login_count, credential_version, permission_version, mfa_required) VALUES (UUID_TO_BIN(?, 0), ?, ?, ?, TRUE, FALSE, 0, 1, 1, FALSE)")) {
            insertUser(statement, ownerId, ownerName, "Batch delete owner");
            insertUser(statement, outsideId, "batch_delete_outside_" + outsideId.substring(0, 8), "Batch delete outside");
        }
    }

    private void insertUser(PreparedStatement statement, String id, String username, String displayName) throws Exception {
        statement.setString(1, id);
        statement.setString(2, username);
        statement.setString(3, PASSWORD_HASH);
        statement.setString(4, displayName);
        statement.addBatch();
        statement.executeBatch();
    }

    private void insertPermissions(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role_permission (role_id, permission_id) SELECT UUID_TO_BIN(?, 0), id FROM sys_permission WHERE code IN ('user:delete', 'user:read')")) {
            statement.setString(1, roleId);
            statement.executeUpdate();
        }
    }

    private void insertUserRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_user_role (user_id, role_id) VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
            statement.setString(1, ownerId);
            statement.setString(2, roleId);
            statement.executeUpdate();
        }
    }

    private void clearLoginRateLimits(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_login_rate_limit")) {
            statement.executeUpdate();
        }
    }

    private void deleteUser(Connection connection, String id) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, id);
            statement.executeUpdate();
        }
    }

    private void deleteRole(Connection connection, String id) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, id);
            statement.executeUpdate();
        }
    }
}
