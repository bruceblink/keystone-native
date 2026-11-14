package app.keystone;

import app.keystone.identity.UuidValues;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.UUID;
import java.util.zip.ZipInputStream;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户 XLSX 导出先应用部门范围，再序列化完整结果集。 */
@QuarkusTest
class UserExportScopeResourceHttpTest {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";
    private static final String ROOT_DEPARTMENT = "ec955baa-6e89-5626-bccf-7106d2d3cb8b";

    @Inject DataSource dataSource;

    private String roleId;
    private String ownDepartmentId;
    private String otherDepartmentId;
    private String actorId;
    private String ownUserId;
    private String otherUserId;
    private String actorUsername;
    private String accessToken;

    @BeforeEach
    void createScopedExportFixture() throws Exception {
        roleId = UuidValues.v7();
        ownDepartmentId = UuidValues.v7();
        otherDepartmentId = UuidValues.v7();
        actorId = UuidValues.v7();
        ownUserId = UuidValues.v7();
        otherUserId = UuidValues.v7();
        actorUsername = "export_scope_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        try (Connection connection = dataSource.getConnection()) {
            clearLoginRateLimits(connection);
            insertDepartments(connection);
            insertRole(connection);
            insertUsers(connection);
            insertRolePermissions(connection);
            insertUserRoles(connection);
        }
        accessToken = login(actorUsername);
    }

    @AfterEach
    void removeScopedExportFixture() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            deleteUsers(connection);
            deleteRole(connection);
            deleteDepartments(connection);
        }
    }

    @Test
    void departmentScopedExportExcludesUsersOutsideTheDepartment() {
        byte[] workbook = given().auth().oauth2(accessToken)
                .when().get("/v1/users/export")
                .then().statusCode(200)
                .contentType(containsString("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .extract().asByteArray();

        String sheet = readWorksheet(workbook);
        assertTrue(sheet.contains(actorUsername));
        assertTrue(sheet.contains("scope-own-user"));
        assertFalse(sheet.contains("scope-outside-user"));
    }

    private void insertDepartments(Connection connection) throws Exception {
        insertDepartment(connection, ownDepartmentId, "scope-own-dept");
        insertDepartment(connection, otherDepartmentId, "scope-other-dept");
    }

    private void insertDepartment(Connection connection, String id, String code) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_dept (id, parent_id, code, name, sort_order, enabled) "
                        + "VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0), ?, ?, 0, TRUE)")) {
            statement.setString(1, id);
            statement.setString(2, ROOT_DEPARTMENT);
            statement.setString(3, code);
            statement.setString(4, code);
            statement.executeUpdate();
        }
    }

    private void insertRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role (id, code, name, enabled, data_scope) "
                        + "VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'DEPARTMENT')")) {
            statement.setString(1, roleId);
            statement.setString(2, "SCOPE_EXPORT_" + roleId.substring(0, 8));
            statement.setString(3, "Scoped export role");
            statement.executeUpdate();
        }
    }

    private void insertUsers(Connection connection) throws Exception {
        insertUser(connection, actorId, actorUsername, ownDepartmentId, "Scoped export actor");
        insertUser(connection, ownUserId, "scope-own-user", ownDepartmentId, "Scoped own user");
        insertUser(connection, otherUserId, "scope-outside-user", otherDepartmentId, "Scoped outside user");
    }

    private void insertUser(Connection connection, String id, String username, String departmentId, String displayName)
            throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_user (id, username, password_hash, display_name, enabled, must_change_password, "
                        + "failed_login_count, credential_version, permission_version, mfa_required, dept_id) "
                        + "VALUES (UUID_TO_BIN(?, 0), ?, ?, ?, TRUE, FALSE, 0, 1, 1, FALSE, UUID_TO_BIN(?, 0))")) {
            statement.setString(1, id);
            statement.setString(2, username);
            statement.setString(3, PASSWORD_HASH);
            statement.setString(4, displayName);
            statement.setString(5, departmentId);
            statement.executeUpdate();
        }
    }

    private void insertRolePermissions(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role_permission (role_id, permission_id) "
                        + "SELECT UUID_TO_BIN(?, 0), id FROM sys_permission")) {
            statement.setString(1, roleId);
            statement.executeUpdate();
        }
    }

    private void insertUserRoles(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_user_role (user_id, role_id) VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
            statement.setString(1, actorId);
            statement.setString(2, roleId);
            statement.executeUpdate();
        }
    }

    private void deleteUsers(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM sys_user WHERE id IN (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
            statement.setString(1, actorId);
            statement.setString(2, ownUserId);
            statement.setString(3, otherUserId);
            statement.executeUpdate();
        }
    }

    private void deleteRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, roleId);
            statement.executeUpdate();
        }
    }

    private void deleteDepartments(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM sys_dept WHERE id IN (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
            statement.setString(1, ownDepartmentId);
            statement.setString(2, otherDepartmentId);
            statement.executeUpdate();
        }
    }

    private void clearLoginRateLimits(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_login_rate_limit")) {
            statement.executeUpdate();
        }
    }

    private String login(String username) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }

    private static String readWorksheet(byte[] workbook) {
        try (var zip = new ZipInputStream(new ByteArrayInputStream(workbook), StandardCharsets.UTF_8)) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                if ("xl/worksheets/sheet1.xml".equals(entry.getName())) {
                    return new String(zip.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
            throw new AssertionError("worksheet is missing");
        } catch (java.io.IOException e) {
            throw new AssertionError("invalid Excel workbook", e);
        }
    }
}
