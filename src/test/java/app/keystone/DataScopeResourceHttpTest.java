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

/** 验证受限主体通过真实 HTTP 访问非用户资源时统一拒绝越界请求。 */
@QuarkusTest
class DataScopeResourceHttpTest {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";

    @Inject DataSource dataSource;

    private String roleId;
    private String userId;
    private String username;
    private String accessToken;

    @BeforeEach
    void createRestrictedSubject() throws Exception {
        roleId = UuidValues.v7();
        userId = UuidValues.v7();
        username = "scope_http_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        try (Connection connection = dataSource.getConnection()) {
            clearLoginRateLimits(connection);
            insertRole(connection);
            insertUser(connection);
            insertRolePermissions(connection);
            insertUserRole(connection);
        }
        accessToken = login();
    }

    @AfterEach
    void removeRestrictedSubject() throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, userId);
            statement.executeUpdate();
        }
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, roleId);
            statement.executeUpdate();
        }
    }

    @Test
    void restrictedSubjectCannotReadOrWriteGlobalResources() {
        assertDeniedGet("/v1/roles");
        assertDeniedPost("/v1/roles");
        assertDeniedGet("/v1/posts");
        assertDeniedPost("/v1/posts");
        assertDeniedGet("/v1/menus");
        assertDeniedPost("/v1/menus");
        assertDeniedGet("/v1/configs");
        assertDeniedPost("/v1/configs");
        assertDeniedGet("/v1/dictionaries");
        assertDeniedPost("/v1/dictionaries");
        assertDeniedGet("/v1/operation-logs");
        assertDeniedGet("/v1/monitor/security");
        assertDeniedGet("/v1/monitor/security/report");
        assertDeniedGet("/v1/monitor/onlineUsers");
        assertDeniedGet("/v1/jobs");
        assertDeniedPost("/v1/jobs");
        assertDeniedGet("/v1/notices/manage");
        assertDeniedPost("/v1/notices");
        assertDeniedGet("/v1/file/download?fileName=missing.txt");
        assertDeniedFileUpload();
    }

    private void assertDeniedGet(String path) {
        given().auth().oauth2(accessToken)
                .when().get(path)
                .then().statusCode(403);
    }

    private void assertDeniedPost(String path) {
        given().auth().oauth2(accessToken).contentType(JSON)
                .body("{}")
                .when().post(path)
                .then().statusCode(403)
                .body("error.code", is("data_scope_denied"));
    }

    private void assertDeniedFileUpload() {
        given().auth().oauth2(accessToken)
                .multiPart("file", "scope.txt", "scope test".getBytes(), "text/plain")
                .when().post("/v1/file/upload")
                .then().statusCode(403);
    }

    private String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private void insertRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'SELF')")) {
            statement.setString(1, roleId);
            statement.setString(2, "SCOPE_HTTP_" + roleId.substring(0, 8));
            statement.setString(3, "HTTP scope test role");
            statement.executeUpdate();
        }
    }

    private void clearLoginRateLimits(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_login_rate_limit")) {
            statement.executeUpdate();
        }
    }

    private void insertUser(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_user (id, username, password_hash, display_name, enabled, must_change_password, failed_login_count, credential_version, permission_version, mfa_required) "
                        + "VALUES (UUID_TO_BIN(?, 0), ?, ?, ?, TRUE, FALSE, 0, 1, 1, FALSE)")) {
            statement.setString(1, userId);
            statement.setString(2, username);
            statement.setString(3, PASSWORD_HASH);
            statement.setString(4, "HTTP scope test user");
            statement.executeUpdate();
        }
    }

    private void insertRolePermissions(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role_permission (role_id, permission_id) SELECT UUID_TO_BIN(?, 0), id FROM sys_permission")) {
            statement.setString(1, roleId);
            statement.executeUpdate();
        }
    }

    private void insertUserRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_user_role (user_id, role_id) VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
            statement.setString(1, userId);
            statement.setString(2, roleId);
            statement.executeUpdate();
        }
    }
}
