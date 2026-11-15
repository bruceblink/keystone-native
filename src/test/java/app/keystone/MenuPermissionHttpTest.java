package app.keystone;

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

/** 验证菜单树读取需要显式的 menu:read 权限。 */
@QuarkusTest
class MenuPermissionHttpTest extends AuthTestFixture {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";

    @Inject DataSource dataSource;

    private String roleId;
    private String userId;
    private String username;

    @BeforeEach
    void createSubjectWithoutMenuRead() throws Exception {
        roleId = UUID.randomUUID().toString();
        userId = UUID.randomUUID().toString();
        username = "menu_denied_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);

        try (Connection connection = dataSource.getConnection()) {
            insertRole(connection);
            insertUser(connection);
            insertUserRole(connection);
        }
    }

    @AfterEach
    void removeSubject() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_user_role WHERE user_id = UUID_TO_BIN(?, 0)")) {
                statement.setString(1, userId);
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
                statement.setString(1, userId);
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)")) {
                statement.setString(1, roleId);
                statement.executeUpdate();
            }
        }
    }

    @Test
    void menuTreeRejectsSubjectWithoutReadPermission() {
        String token = given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");

        given().auth().oauth2(token)
                .when().get("/v1/menus")
                .then().statusCode(403)
                .body("error.code", is("permission_denied"));
    }

    private void insertRole(Connection connection) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'ALL')")) {
            statement.setString(1, roleId);
            statement.setString(2, "MENU_DENIED_" + roleId.substring(0, 8));
            statement.setString(3, "Menu denied test role");
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
            statement.setString(4, "Menu denied test user");
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
