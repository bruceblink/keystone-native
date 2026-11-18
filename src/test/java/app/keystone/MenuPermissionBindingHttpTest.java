package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用真实 HTTP 和 MySQL 核验菜单权限标识的授权、目录状态及清空行为。 */
@QuarkusTest
class MenuPermissionBindingHttpTest extends AuthTestFixture {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";

    @Inject DataSource dataSource;

    private final List<String> menuIds = new ArrayList<>();
    private final List<TestSubject> subjects = new ArrayList<>();

    @AfterEach
    void removeSyntheticRowsAndRestoreCatalog() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE sys_permission SET status = 1, deprecated = FALSE WHERE code = 'user:read'")) {
                statement.executeUpdate();
            }
            for (String menuId : menuIds) deleteMenu(connection, menuId);
            for (TestSubject subject : subjects) deleteSubject(connection, subject);
        }
    }

    @Test
    void permissionRequiresMenuManageAndUnauthorizedWritesDoNotChangeData() throws Exception {
        String suffix = UUID.randomUUID().toString().replace("-", "");
        TestSubject subject = createSubject("menu:create", "menu:update");
        String limitedToken = login(subject.username());
        String deniedCode = "menu_permission_denied_" + suffix;
        given().auth().oauth2(limitedToken).contentType(JSON)
                .body(menuRequest(deniedCode, "user:read"))
                .when().post("/v1/menus")
                .then().statusCode(403)
                .body("error.code", is("permission_denied"));

        assertEquals(0, menuCountByCode(deniedCode));

        String admin = loginAdmin();
        String existingId = createMenu(admin, "menu_permission_existing_" + suffix, "user:read");
        int oldLinkCount = permissionLinkCount(existingId);
        given().auth().oauth2(limitedToken).contentType(JSON)
                .body("{\"permission\":null}")
                .when().put("/v1/menus/" + existingId)
                .then().statusCode(403)
                .body("error.code", is("permission_denied"));

        assertEquals(oldLinkCount, permissionLinkCount(existingId));
        assertEquals("user:read", legacyPermission(existingId));
    }

    @Test
    void createAndUpdateAcceptOnlyActiveCurrentCatalogEntries() throws Exception {
        String admin = loginAdmin();
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String unknownCode = "menu_permission_unknown_" + suffix;
        given().auth().oauth2(admin).contentType(JSON)
                .body(menuRequest(unknownCode, "unknown:permission"))
                .when().post("/v1/menus")
                .then().statusCode(422)
                .body("error.code", is("validation_failed"));
        assertEquals(0, menuCountByCode(unknownCode));

        setCatalogState(0, false);
        String disabledCode = "menu_permission_disabled_" + suffix;
        given().auth().oauth2(admin).contentType(JSON)
                .body(menuRequest(disabledCode, "user:read"))
                .when().post("/v1/menus")
                .then().statusCode(422)
                .body("error.code", is("validation_failed"));
        assertEquals(0, menuCountByCode(disabledCode));

        setCatalogState(1, true);
        String deprecatedCode = "menu_permission_deprecated_" + suffix;
        given().auth().oauth2(admin).contentType(JSON)
                .body(menuRequest(deprecatedCode, "user:read"))
                .when().post("/v1/menus")
                .then().statusCode(422)
                .body("error.code", is("validation_failed"));
        assertEquals(0, menuCountByCode(deprecatedCode));

        setCatalogState(1, false);
        String validId = createMenu(admin, "menu_permission_valid_" + suffix, "user:read");
        menuIds.add(validId);
        assertEquals(1, permissionLinkCount(validId));
        assertEquals("user:read", legacyPermission(validId));
    }

    @Test
    void explicitNullAndBlankClearWhileOmittedPermissionIsRetained() throws Exception {
        String admin = loginAdmin();
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String nullId = createMenu(admin, "menu_permission_null_" + suffix, "user:read");

        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"permission retained\"}")
                .when().put("/v1/menus/" + nullId)
                .then().statusCode(200)
                .body("data.permission", is("user:read"));
        assertEquals(1, permissionLinkCount(nullId));

        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"permission\":null}")
                .when().put("/v1/menus/" + nullId)
                .then().statusCode(200)
                .body("data.permission", org.hamcrest.Matchers.nullValue());
        assertEquals(0, permissionLinkCount(nullId));
        assertNull(legacyPermission(nullId));

        String blankId = createMenu(admin, "menu_permission_blank_" + suffix, "user:read");
        menuIds.add(blankId);
        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"permission\":\"  \"}")
                .when().put("/v1/menus/" + blankId)
                .then().statusCode(200)
                .body("data.permission", org.hamcrest.Matchers.nullValue());
        assertEquals(0, permissionLinkCount(blankId));
        assertNull(legacyPermission(blankId));
    }

    @Test
    void inactiveAndDeprecatedDirectoryRowsAreRemovedFromRolesAndCapabilities() throws Exception {
        TestSubject subject = createSubject("user:read");
        String token = login(subject.username());

        assertTrue(capabilities(token).contains("user:read"));
        assertTrue(rolePermissions(subject.roleCode()).contains("user:read"));
        assertMenuPermission("user:read");

        setCatalogState(0, false);
        assertFalse(capabilities(token).contains("user:read"));
        assertFalse(rolePermissions(subject.roleCode()).contains("user:read"));
        assertMenuPermission(null);

        setCatalogState(1, true);
        assertFalse(capabilities(token).contains("user:read"));
        assertFalse(rolePermissions(subject.roleCode()).contains("user:read"));
        assertMenuPermission(null);
    }

    /** 通过真实菜单接口确认停用或废弃的关联不会继续对前端展示。 */
    private void assertMenuPermission(String expected) {
        String token = loginAdmin();
        var response = given().auth().oauth2(token)
                .when().get("/v1/menus")
                .then().statusCode(200)
                .extract().as(com.fasterxml.jackson.databind.JsonNode.class);
        var actual = findMenuPermission(response.path("data"), "system:user");
        assertEquals(expected, actual);
    }

    private String findMenuPermission(com.fasterxml.jackson.databind.JsonNode nodes, String code) {
        for (var node : nodes) {
            var menu = node.path("menu");
            if (code.equals(menu.path("code").asText())) {
                return menu.path("permission").isNull() ? null : menu.path("permission").asText();
            }
            var nested = findMenuPermission(node.path("children"), code);
            if (nested != null) return nested;
        }
        return null;
    }

    private String createMenu(String token, String code, String permission) {
        String id = given().auth().oauth2(token).contentType(JSON)
                .body(menuRequest(code, permission))
                .when().post("/v1/menus")
                .then().statusCode(201)
                .body("data.permission", is(permission))
                .extract().path("data.id");
        menuIds.add(id);
        return id;
    }

    private TestSubject createSubject(String... permissionCodes) throws Exception {
        String roleId = UUID.randomUUID().toString();
        String userId = UUID.randomUUID().toString();
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String roleCode = "MENU_PERMISSION_" + suffix;
        String username = "menu_permission_" + suffix;
        try (Connection connection = dataSource.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'ALL')")) {
                statement.setString(1, roleId);
                statement.setString(2, roleCode);
                statement.setString(3, "菜单权限测试角色");
                statement.executeUpdate();
            }
            for (String permission : permissionCodes) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO sys_role_permission (role_id, permission_id) SELECT UUID_TO_BIN(?, 0), id FROM sys_permission WHERE code = ?")) {
                    statement.setString(1, roleId);
                    statement.setString(2, permission);
                    assertEquals(1, statement.executeUpdate());
                }
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO sys_user (id, username, password_hash, display_name, enabled, must_change_password, failed_login_count, credential_version, permission_version, mfa_required) "
                            + "VALUES (UUID_TO_BIN(?, 0), ?, ?, ?, TRUE, FALSE, 0, 1, 1, FALSE)")) {
                statement.setString(1, userId);
                statement.setString(2, username);
                statement.setString(3, PASSWORD_HASH);
                statement.setString(4, "菜单权限测试用户");
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO sys_user_role (user_id, role_id) VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
                statement.setString(1, userId);
                statement.setString(2, roleId);
                statement.executeUpdate();
            }
        }
        TestSubject subject = new TestSubject(roleId, userId, roleCode, username);
        subjects.add(subject);
        return subject;
    }

    private void deleteSubject(Connection connection, TestSubject subject) throws Exception {
        String[] statements = {
                "DELETE FROM sys_refresh_token WHERE user_id = UUID_TO_BIN(?, 0)",
                "DELETE FROM sys_auth_session WHERE user_id = UUID_TO_BIN(?, 0)",
                "DELETE FROM sys_user_role WHERE user_id = UUID_TO_BIN(?, 0)",
                "DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)",
                "DELETE FROM sys_role_permission WHERE role_id = UUID_TO_BIN(?, 0)",
                "DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)"
        };
        for (int index = 0; index < statements.length; index++) {
            try (PreparedStatement statement = connection.prepareStatement(statements[index])) {
                statement.setString(1, index < 4 ? subject.userId() : subject.roleId());
                statement.executeUpdate();
            }
        }
    }

    private void deleteMenu(Connection connection, String menuId) throws Exception {
        for (String table : List.of("sys_menu_permission", "sys_role_menu")) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "DELETE FROM " + table + " WHERE menu_id = UUID_TO_BIN(?, 0)")) {
                statement.setString(1, menuId);
                statement.executeUpdate();
            }
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM sys_menu WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, menuId);
            statement.executeUpdate();
        }
    }

    private int menuCountByCode(String code) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM sys_menu WHERE code = ?")) {
            statement.setString(1, code);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private int permissionLinkCount(String menuId) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM sys_menu_permission WHERE menu_id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, menuId);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private String legacyPermission(String menuId) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT permission FROM sys_menu WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, menuId);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getString(1);
            }
        }
    }

    private void setCatalogState(int status, boolean deprecated) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE sys_permission SET status = ?, deprecated = ? WHERE code = 'user:read'")) {
            statement.setInt(1, status);
            statement.setBoolean(2, deprecated);
            assertEquals(1, statement.executeUpdate());
        }
    }

    private List<String> capabilities(String token) {
        return given().auth().oauth2(token)
                .when().get("/v1/auth/me/capabilities")
                .then().statusCode(200)
                .extract().path("data.permissions");
    }

    private List<String> rolePermissions(String roleCode) {
        return given().auth().oauth2(loginAdmin()).queryParam("keyword", roleCode)
                .when().get("/v1/roles")
                .then().statusCode(200)
                .extract().path("data.items[0].permissions");
    }

    private String login(String username) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private static String loginAdmin() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private static String menuRequest(String code, String permission) {
        return "{\"code\":\"" + code + "\",\"name\":\"权限目录测试菜单\",\"menuType\":\"MENU\",\"permission\":"
                + (permission == null ? "null" : "\"" + permission + "\"") + ",\"enabled\":true}";
    }

    private record TestSubject(String roleId, String userId, String roleCode, String username) { }
}
