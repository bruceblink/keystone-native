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

            given().auth().oauth2(token).contentType(JSON)
                    .body("{}")
                    .when().put("/v1/menus/" + id + "/roles")
                    .then().statusCode(422)
                    .body("error.code", is("validation_failed"));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"roleCodes\":\"ADMIN\"}")
                    .when().put("/v1/menus/" + id + "/roles")
                    .then().statusCode(422)
                    .body("error.code", is("validation_failed"));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"roleCodes\":[\"MISSING\"]}")
                    .when().put("/v1/menus/" + id + "/roles")
                    .then().statusCode(422)
                    .body("message", is("角色编码无效"));
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
    void managerCanKeepOrRemoveBoundDisabledRolesButCannotAddAnotherDisabledRole() throws SQLException {
        String token = login();
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String menuId = createMenu(token, "disabled_role_menu_" + suffix, null);
        String boundRoleId = UUID.randomUUID().toString();
        String unboundRoleId = UUID.randomUUID().toString();
        String boundRoleCode = "DISABLED_BOUND_" + suffix;
        String unboundRoleCode = "DISABLED_UNBOUND_" + suffix;
        try {
            try (var connection = dataSource.getConnection()) {
                insertDisabledRole(connection, boundRoleId, boundRoleCode);
                insertDisabledRole(connection, unboundRoleId, unboundRoleCode);
                insertRoleMenu(connection, boundRoleId, menuId);
            }

            given().auth().oauth2(token)
                    .when().get("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(200)
                    .body("data.roleCodes", hasItem(boundRoleCode));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"roleCodes\":[\"ADMIN\",\"" + boundRoleCode + "\"]}")
                    .when().put("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(200)
                    .body("data.updated", is(true));

            given().auth().oauth2(token)
                    .when().get("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(200)
                    .body("data.roleCodes", hasItem("ADMIN"))
                    .body("data.roleCodes", hasItem(boundRoleCode));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"roleCodes\":[\"ADMIN\"]}")
                    .when().put("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(200);

            given().auth().oauth2(token)
                    .when().get("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(200)
                    .body("data.roleCodes", hasItem("ADMIN"))
                    .body("data.roleCodes", org.hamcrest.Matchers.not(hasItem(boundRoleCode)));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"roleCodes\":[\"ADMIN\",\"" + unboundRoleCode + "\"]}")
                    .when().put("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(422)
                    .body("message", is("角色编码无效"));

            given().auth().oauth2(token)
                    .when().get("/v1/menus/" + menuId + "/roles")
                    .then().statusCode(200)
                    .body("data.roleCodes", hasItem("ADMIN"))
                    .body("data.roleCodes", org.hamcrest.Matchers.not(hasItem(unboundRoleCode)));
        } finally {
            try {
                deleteMenu(token, menuId);
            } finally {
                deleteSyntheticRoles(boundRoleId, unboundRoleId);
            }
        }
    }

    @Test
    void managerCanMoveMenuAndRejectsMissingOrCyclicParents() {
        String token = login();
        String rootId = createMenu(token, "move_root_" + UUID.randomUUID(), null);
        String replacementRootId = createMenu(token, "move_replacement_" + UUID.randomUUID(), null);
        String childId = createMenu(token, "move_child_" + UUID.randomUUID(), rootId);
        String grandchildId = createMenu(token, "move_grandchild_" + UUID.randomUUID(), childId);
        try {
            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"parentId\":\"" + replacementRootId + "\",\"name\":\"移动子菜单\",\"menuType\":\"MENU\",\"enabled\":true}")
                    .when().put("/v1/menus/" + childId)
                    .then().statusCode(200)
                    .body("data.parentId", is(replacementRootId));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"parentId\":\"" + UUID.randomUUID() + "\",\"name\":\"非法父级\",\"menuType\":\"MENU\"}")
                    .when().put("/v1/menus/" + childId)
                    .then().statusCode(422)
                    .body("message", is("parent menu does not exist"));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"parentId\":\"" + childId + "\",\"name\":\"环引用\",\"menuType\":\"MENU\"}")
                    .when().put("/v1/menus/" + replacementRootId)
                    .then().statusCode(422)
                    .body("message", is("menu cannot be nested under its descendant"));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"parentId\":\"" + replacementRootId + "\",\"name\":\"自身引用\",\"menuType\":\"MENU\"}")
                    .when().put("/v1/menus/" + replacementRootId)
                    .then().statusCode(422)
                    .body("message", is("menu cannot be nested under its descendant"));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"parentId\":null,\"name\":\"移动到根\",\"menuType\":\"MENU\"}")
                    .when().put("/v1/menus/" + childId)
                    .then().statusCode(200)
                    .body("data.parentId", org.hamcrest.Matchers.nullValue());
        } finally {
            deleteMenu(token, grandchildId);
            deleteMenu(token, childId);
            deleteMenu(token, replacementRootId);
            deleteMenu(token, rootId);
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

    /** 创建未绑定的停用角色，用于核验 API 不能通过菜单新授予它。 */
    private static void insertDisabledRole(java.sql.Connection connection, String roleId, String code) throws SQLException {
        try (var statement = connection.prepareStatement(
                "INSERT INTO sys_role(id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?), ?, ?, FALSE, 'ALL')")) {
            statement.setString(1, roleId);
            statement.setString(2, code);
            statement.setString(3, code);
            statement.executeUpdate();
        }
    }

    private void deleteSyntheticRoles(String firstRoleId, String secondRoleId) throws SQLException {
        try (var connection = dataSource.getConnection()) {
            for (String table : new String[]{"sys_role_menu", "sys_role_permission"}) {
                try (var statement = connection.prepareStatement(
                        "DELETE FROM " + table + " WHERE role_id IN (UUID_TO_BIN(?), UUID_TO_BIN(?))")) {
                    statement.setString(1, firstRoleId);
                    statement.setString(2, secondRoleId);
                    statement.executeUpdate();
                }
            }
            try (var statement = connection.prepareStatement(
                    "DELETE FROM sys_role WHERE id IN (UUID_TO_BIN(?), UUID_TO_BIN(?))")) {
                statement.setString(1, firstRoleId);
                statement.setString(2, secondRoleId);
                statement.executeUpdate();
            }
        }
    }

    private static String createMenu(String token, String code, String parentId) {
        String parent = parentId == null ? "null" : "\"" + parentId + "\"";
        return given().auth().oauth2(token).contentType(JSON)
                .body("{\"parentId\":" + parent + ",\"code\":\"" + code + "\",\"name\":\"" + code + "\",\"menuType\":\"MENU\",\"enabled\":true}")
                .when().post("/v1/menus")
                .then().statusCode(201)
                .extract().path("data.id");
    }

    private static void deleteMenu(String token, String id) {
        given().auth().oauth2(token).when().delete("/v1/menus/" + id).then().statusCode(200);
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
