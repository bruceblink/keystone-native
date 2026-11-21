package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.SQLException;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证用户通用编辑在停用账号时同步撤销会话。 */
@QuarkusTest
class UserUpdateSessionRevocationTest extends AuthTestFixture {
    @Inject DataSource sessionDataSource;

    /** 验证通用编辑和专用状态接口都撤销停用用户的旧访问与刷新会话。 */
    @Test
    void disablingThroughUserUpdateRevokesAccessAndRefreshSessions() throws SQLException {
        String admin = login("admin", "password");
        String username = "disable_update_" + System.nanoTime();
        String userId = createUser(admin, username);
        var credentials = loginResult(username, "password");

        try {
            assertEquals(1, activeCount("sys_auth_session", username));
            assertEquals(1, activeCount("sys_refresh_token", username));

            given().auth().oauth2(admin).contentType(JSON).body("{\"enabled\":false}")
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(200).body("data.enabled", is(false));

            // 直接检查持久化状态，避免仅凭停用账号被认证层拒绝来判断会话已撤销。
            assertEquals(0, activeCount("sys_auth_session", username));
            assertEquals(0, activeCount("sys_refresh_token", username));
            given().auth().oauth2(credentials.accessToken())
                    .when().get("/v1/profile").then().statusCode(401);
            given().contentType(JSON).body("{\"refreshToken\":\"" + credentials.refreshToken() + "\"}")
                    .when().post("/v1/auth/refresh").then().statusCode(401);

            given().auth().oauth2(admin).contentType(JSON).body("{\"displayName\":\"Still disabled\"}")
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(200).body("data.enabled", is(false));
            assertEquals(0, activeCount("sys_auth_session", username));

            // 重新启用后建立新会话，再次停用必须撤销新会话。
            given().auth().oauth2(admin).contentType(JSON).body("{\"enabled\":true}")
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(200).body("data.enabled", is(true));
            var reenabledCredentials = loginResult(username, "password");
            assertEquals(1, activeCount("sys_auth_session", username));
            given().auth().oauth2(admin).contentType(JSON).body("{\"enabled\":false}")
                    .when().put("/v1/users/" + userId + "/status")
                    .then().statusCode(200).body("data.enabled", is(false));
            assertEquals(0, activeCount("sys_auth_session", username));
            assertEquals(0, activeCount("sys_refresh_token", username));
            given().auth().oauth2(reenabledCredentials.accessToken())
                    .when().get("/v1/profile").then().statusCode(401);
            given().contentType(JSON).body("{\"refreshToken\":\"" + reenabledCredentials.refreshToken() + "\"}")
                    .when().post("/v1/auth/refresh").then().statusCode(401);
        } finally {
            deleteUser(admin, userId);
        }
    }

    /** 验证请求失败或未提交 enabled 时保留现有认证会话。 */
    @Test
    void editingProfileWithoutEnabledFieldPreservesTheExistingSession() throws SQLException {
        String admin = login("admin", "password");
        String username = "edit_session_" + System.nanoTime();
        String userId = createUser(admin, username);
        var credentials = loginResult(username, "password");

        try {
            // 资料校验失败时，接口不能撤销本次请求用户的有效会话。
            String missingRole = "missing_role_" + System.nanoTime();
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"enabled\":false,\"roleCodes\":[\"" + missingRole + "\"]}")
                    .when().put("/v1/users/" + userId).then().statusCode(422);
            assertEquals(1, activeCount("sys_auth_session", username));
            assertEquals(1, activeCount("sys_refresh_token", username));

            given().auth().oauth2(admin).contentType(JSON).body("{\"displayName\":\"Edited display name\"}")
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(200).body("data.displayName", is("Edited display name"));

            assertEquals(1, activeCount("sys_auth_session", username));
            assertEquals(1, activeCount("sys_refresh_token", username));
            given().auth().oauth2(credentials.accessToken())
                    .when().get("/v1/profile").then().statusCode(200)
                    .body("data.displayName", is("Edited display name"));
            given().contentType(JSON).body("{\"refreshToken\":\"" + credentials.refreshToken() + "\"}")
                    .when().post("/v1/auth/refresh").then().statusCode(200);
        } finally {
            deleteUser(admin, userId);
        }
    }

    /** 创建用于隔离验证的普通用户，并返回服务端生成的 UUID。 */
    private static String createUser(String admin, String username) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Session test\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
    }

    /** 登录并保留短时访问令牌与刷新令牌，用于停用前后比较。 */
    private static LoginResult loginResult(String username, String password) {
        var result = given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        return new LoginResult(result.path("data.accessToken"), result.path("data.refreshToken"));
    }

    /** 以管理员账号登录并返回访问令牌。 */
    private static String login(String username, String password) {
        return loginResult(username, password).accessToken();
    }

    /** 按唯一用户名读取仍可使用的会话或刷新令牌数量。 */
    private int activeCount(String table, String username) throws SQLException {
        String query = "SELECT COUNT(*) FROM " + table + " record JOIN sys_user account ON record.user_id = account.id "
                + "WHERE account.username = ? AND record.revoked_at IS NULL";
        try (var connection = sessionDataSource.getConnection(); var statement = connection.prepareStatement(query)) {
            statement.setString(1, username);
            try (var result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getInt(1);
            }
        }
    }

    /** 使用管理员会话移除测试账号，避免测试数据留在隔离数据库中。 */
    private static void deleteUser(String admin, String userId) {
        given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
    }

    /** 测试只在内存中持有认证令牌，不输出令牌内容。 */
    private record LoginResult(String accessToken, String refreshToken) {}
}
