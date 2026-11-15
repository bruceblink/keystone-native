package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.SQLException;

import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 验证菜单目录和角色绑定的管理接口。 */
@QuarkusTest
class MenuResourceHttpTest extends AuthTestFixture {
    @Inject DataSource dataSource;

    @Test
    void managerCanReadDisabledMenuAndCurrentRoleBindings() {
        String token = login();
        String code = "http_menu_" + UUID.randomUUID().toString().replace("-", "");
        String id = null;
        try {
            id = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"code\":\"" + code + "\",\"name\":\"HTTP menu\",\"menuType\":\"MENU\",\"enabled\":false}")
                    .when().post("/v1/menus")
                    .then().statusCode(201)
                    .body("data.enabled", is(false))
                    .extract().path("data.id");

            given().auth().oauth2(token)
                    .when().get("/v1/menus")
                    .then().statusCode(200)
                    .body("data.menu.code", hasItem(code));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"roleCodes\":[\"ADMIN\"]}")
                    .when().put("/v1/menus/" + id + "/roles")
                    .then().statusCode(200)
                    .body("data.updated", is(true));

            given().auth().oauth2(token)
                    .when().get("/v1/menus/" + id + "/roles")
                    .then().statusCode(200)
                    .body("data.roleCodes", hasItem("ADMIN"));
        } finally {
            if (id != null) {
                given().auth().oauth2(token).contentType(JSON)
                        .body("{\"roleCodes\":[]}")
                        .when().put("/v1/menus/" + id + "/roles");
                given().auth().oauth2(token).when().delete("/v1/menus/" + id);
            }
        }
    }

    @Test
    void menuRoleLookupReturnsNotFoundForUnknownMenu() {
        String token = login();

        given().auth().oauth2(token)
                .when().get("/v1/menus/" + UUID.randomUUID() + "/roles")
                .then().statusCode(404)
                .body("success", is(false));
    }

    @Test
    void ordinaryReaderSeesOnlyEnabledMenusAssignedToItsRole() throws Exception {
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String roleId = UUID.randomUUID().toString();
        String userId = UUID.randomUUID().toString();
        String activeId = UUID.randomUUID().toString();
        String disabledId = UUID.randomUUID().toString();
        String unassignedId = UUID.randomUUID().toString();
        String username = "menu_reader_" + suffix;
        try {
            createReaderFixture(roleId, userId, activeId, disabledId, unassignedId, username, suffix);
            String token = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login")
                    .then().statusCode(200)
                    .extract().path("data.accessToken");

            given().auth().oauth2(token)
                    .when().get("/v1/menus")
                    .then().statusCode(200)
                    .body("data.menu.code", hasItem("reader.active." + suffix))
                    .body("data.menu.code", org.hamcrest.Matchers.not(hasItem("reader.disabled." + suffix)))
                    .body("data.menu.code", org.hamcrest.Matchers.not(hasItem("reader.unassigned." + suffix)));

            given().auth().oauth2(token)
                    .when().get("/v1/menus/dropdown")
                    .then().statusCode(200)
                    .body("data.code", hasItem("reader.active." + suffix))
                    .body("data.code", org.hamcrest.Matchers.not(hasItem("reader.disabled." + suffix)))
                    .body("data.code", org.hamcrest.Matchers.not(hasItem("reader.unassigned." + suffix)));
        } finally {
            deleteReaderFixture(roleId, userId, activeId, disabledId, unassignedId);
        }
    }

    private void createReaderFixture(String roleId, String userId, String activeId, String disabledId,
                                     String unassignedId, String username, String suffix) throws SQLException {
        try (var connection = dataSource.getConnection()) {
            insertRole(connection, roleId, "MENU_READER_" + username);
            insertUser(connection, userId, roleId, username);
            grantPermission(connection, roleId, "menu:read");
            insertMenu(connection, activeId, "reader.active." + suffix, true);
            insertMenu(connection, disabledId, "reader.disabled." + suffix, false);
            insertMenu(connection, unassignedId, "reader.unassigned." + suffix, true);
            insertRoleMenu(connection, roleId, activeId);
            insertRoleMenu(connection, roleId, disabledId);
        }
    }

    private void deleteReaderFixture(String roleId, String userId, String activeId, String disabledId,
                                     String unassignedId) throws SQLException {
        try (var connection = dataSource.getConnection()) {
            for (String sql : new String[]{
                    "DELETE FROM sys_role_menu WHERE role_id = UUID_TO_BIN(?)",
                    "DELETE FROM sys_user_role WHERE role_id = UUID_TO_BIN(?)",
                    "DELETE FROM sys_role_permission WHERE role_id = UUID_TO_BIN(?)",
                    "DELETE FROM sys_user WHERE id = UUID_TO_BIN(?)",
                    "DELETE FROM sys_role WHERE id = UUID_TO_BIN(?)",
                    "DELETE FROM sys_menu WHERE id IN (UUID_TO_BIN(?), UUID_TO_BIN(?), UUID_TO_BIN(?))"}) {
                try (var statement = connection.prepareStatement(sql)) {
                    if (sql.contains("IN (")) {
                        statement.setString(1, activeId);
                        statement.setString(2, disabledId);
                        statement.setString(3, unassignedId);
                    } else {
                        statement.setString(1, sql.contains("sys_user WHERE") ? userId : sql.contains("sys_role WHERE") ? roleId : roleId);
                    }
                    statement.executeUpdate();
                }
            }
        }
    }

    private static void insertRole(java.sql.Connection connection, String roleId, String code) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO sys_role(id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?), ?, ?, TRUE, 'ALL')")) {
            statement.setString(1, roleId);
            statement.setString(2, code);
            statement.setString(3, code);
            statement.executeUpdate();
        }
    }

    private static void insertUser(java.sql.Connection connection, String userId, String roleId, String username) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO sys_user(id, username, password_hash, display_name, enabled, must_change_password, failed_login_count, credential_version, permission_version, mfa_required) VALUES (UUID_TO_BIN(?), ?, '$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W', ?, TRUE, FALSE, 0, 1, 1, 0)")) {
            statement.setString(1, userId);
            statement.setString(2, username);
            statement.setString(3, username);
            statement.executeUpdate();
        }
        try (var statement = connection.prepareStatement("INSERT INTO sys_user_role(user_id, role_id) VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?))")) {
            statement.setString(1, userId);
            statement.setString(2, roleId);
            statement.executeUpdate();
        }
    }

    private static void grantPermission(java.sql.Connection connection, String roleId, String permission) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO sys_role_permission(role_id, permission_id) SELECT UUID_TO_BIN(?), id FROM sys_permission WHERE code = ?")) {
            statement.setString(1, roleId);
            statement.setString(2, permission);
            statement.executeUpdate();
        }
    }

    private static void insertMenu(java.sql.Connection connection, String id, String code, boolean enabled) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO sys_menu(id, code, name, menu_type, sort_order, enabled) VALUES (UUID_TO_BIN(?), ?, ?, 'MENU', 0, ?)")) {
            statement.setString(1, id);
            statement.setString(2, code);
            statement.setString(3, code);
            statement.setBoolean(4, enabled);
            statement.executeUpdate();
        }
    }

    private static void insertRoleMenu(java.sql.Connection connection, String roleId, String menuId) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO sys_role_menu(role_id, menu_id) VALUES (UUID_TO_BIN(?), UUID_TO_BIN(?))")) {
            statement.setString(1, roleId);
            statement.setString(2, menuId);
            statement.executeUpdate();
        }
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
