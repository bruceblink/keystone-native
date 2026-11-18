package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.QuarkusTestProfile;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** 使用真实 HTTP 和数据库验证密码策略错误码及失败时的数据边界。 */
@QuarkusTest
@TestProfile(PasswordPolicyHttpTest.StrictPolicyProfile.class)
class PasswordPolicyHttpTest extends AuthTestFixture {
    private static final String INITIAL_PASSWORD = "StartStrong!123";

    @Test
    void userCreationReturnsDedicatedCodeForEveryPasswordPolicyFailure() throws Exception {
        String admin = loginAdmin();
        long suffix = System.nanoTime();
        List<PasswordCase> cases = List.of(
                new PasswordCase("policy_required_" + suffix, null, false, "password_required"),
                new PasswordCase("policy_blank_" + suffix, "", true, "password_required"),
                new PasswordCase("policy_short_" + suffix, "Short!1", true, "password_too_short"),
                new PasswordCase("policy_denied_" + suffix, "forbidden123!", true, "password_disallowed"),
                new PasswordCase("PolicyUser" + suffix, "PolicyUser" + suffix + "!A", true, "password_contains_username"),
                new PasswordCase("policy_upper_" + suffix, "lowercase123!", true, "password_missing_uppercase"),
                new PasswordCase("policy_lower_" + suffix, "UPPERCASE123!", true, "password_missing_lowercase"),
                new PasswordCase("policy_digit_" + suffix, "NoDigitsHere!!", true, "password_missing_digit"),
                new PasswordCase("policy_special_" + suffix, "NoSpecial1234", true, "password_missing_special"));

        for (PasswordCase value : cases) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("username", value.username());
            if (value.passwordPresent()) body.put("password", value.password());
            body.put("displayName", "Policy failure");
            body.put("roleCodes", List.of("USER"));

            given().auth().oauth2(admin).contentType(JSON).body(body)
                    .when().post("/v1/users")
                    .then().statusCode(422).body("error.code", is(value.code()));
            assertEquals(0, userCount(value.username()), "failed creation must not persist a user");
        }
    }

    @Test
    void createPasswordChangeAndResetFailuresKeepPasswordProfileAndSessionState() throws Exception {
        String admin = loginAdmin();
        String username = "policy_flows_" + System.nanoTime();
        String userId = createAdminUser(admin, username);
        try {
            String userToken = login(username);
            String originalHash = passwordHash(username);
            int originalSessions = activeSessionCount(username);
            String originalName = given().auth().oauth2(admin).when().get("/v1/users/" + userId)
                    .then().statusCode(200).extract().path("data.displayName");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"displayName\":\"Must remain unchanged\",\"password\":\"NoDigitsHere!!\"}")
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(422).body("error.code", is("password_missing_digit"));
            assertUnchanged(username, originalHash, originalSessions, userToken);
            given().auth().oauth2(admin).when().get("/v1/users/" + userId)
                    .then().statusCode(200).body("data.displayName", is(originalName));

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"password\":\"UPPERCASE123!\"}")
                    .when().put("/v1/users/" + userId + "/password")
                    .then().statusCode(422).body("error.code", is("password_missing_lowercase"));
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"password\":\"\"}")
                    .when().put("/v1/users/" + userId + "/password")
                    .then().statusCode(422).body("error.code", is("password_required"));
            assertUnchanged(username, originalHash, originalSessions, userToken);

            given().auth().oauth2(userToken).contentType(JSON)
                    .body("{\"password\":\"lowercase123!\"}")
                    .when().put("/v1/profile/password")
                    .then().statusCode(422).body("error.code", is("password_missing_uppercase"));
            given().auth().oauth2(userToken).contentType(JSON)
                    .body("{\"password\":\"\"}")
                    .when().put("/v1/profile/password")
                    .then().statusCode(422).body("error.code", is("password_required"));
            assertUnchanged(username, originalHash, originalSessions, userToken);
        } finally {
            deleteUser(admin, userId);
        }
    }

    @Test
    void firstPasswordChangeFailureKeepsInitialPasswordAndDoesNotCreateASession() throws Exception {
        String admin = loginAdmin();
        String username = "policy_initial_" + System.nanoTime();
        String userId = createAdminUser(admin, username);
        try {
            setMustChangePassword(userId);
            String originalHash = passwordHash(username);
            int originalSessions = activeSessionCount(username);

            given().contentType(JSON)
                    .body(Map.of("username", username, "currentPassword", INITIAL_PASSWORD))
                    .when().post("/v1/auth/change-initial-password")
                    .then().statusCode(422).body("error.code", is("password_required"));
            given().contentType(JSON)
                    .body(Map.of("username", username, "currentPassword", INITIAL_PASSWORD,
                            "newPassword", "forbidden123!"))
                    .when().post("/v1/auth/change-initial-password")
                    .then().statusCode(422).body("error.code", is("password_disallowed"));

            assertEquals(originalHash, passwordHash(username));
            assertEquals(originalSessions, activeSessionCount(username));
            assertEquals(true, mustChangePassword(userId));
            given().contentType(JSON)
                    .body(Map.of("username", username, "password", INITIAL_PASSWORD))
                    .when().post("/v1/auth/login")
                    .then().statusCode(428).body("error.code", is("precondition_required"));
        } finally {
            deleteUser(admin, userId);
        }
    }

    private String createAdminUser(String admin, String username) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(Map.of("username", username, "password", INITIAL_PASSWORD,
                        "displayName", "Password policy test", "roleCodes", List.of("ADMIN")))
                .when().post("/v1/users")
                .then().statusCode(201)
                .extract().path("data.id");
    }

    private static String login(String username) {
        return login(username, INITIAL_PASSWORD);
    }

    private static String loginAdmin() {
        return login("admin", "password");
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body(Map.of("username", username, "password", password, "forceLogin", true))
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private void assertUnchanged(String username, String hash, int sessions, String token) throws Exception {
        assertEquals(hash, passwordHash(username));
        assertEquals(sessions, activeSessionCount(username));
        given().auth().oauth2(token).when().get("/v1/profile").then().statusCode(200);
    }

    private String passwordHash(String username) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT password_hash FROM sys_user WHERE username = ?")) {
            statement.setString(1, username);
            try (var result = statement.executeQuery()) {
                if (!result.next()) throw new IllegalStateException("test user is missing");
                return result.getString(1);
            }
        }
    }

    private int activeSessionCount(String username) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT COUNT(*) FROM sys_auth_session WHERE user_id = (SELECT id FROM sys_user WHERE username = ?) AND revoked_at IS NULL")) {
            statement.setString(1, username);
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private int userCount(String username) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT COUNT(*) FROM sys_user WHERE username = ?")) {
            statement.setString(1, username);
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private boolean mustChangePassword(String userId) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT must_change_password FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, userId);
            try (var result = statement.executeQuery()) {
                if (!result.next()) throw new IllegalStateException("test user is missing");
                return result.getBoolean(1);
            }
        }
    }

    private void setMustChangePassword(String userId) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("UPDATE sys_user SET must_change_password = true WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, userId);
            assertEquals(1, statement.executeUpdate());
        }
    }

    private static void deleteUser(String admin, String userId) {
        given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
    }

    private record PasswordCase(String username, String password, boolean passwordPresent, String code) { }

    /** 为 HTTP 测试启用全部密码策略，确保各项错误都来自对应短路分支。 */
    public static class StrictPolicyProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "keystone.security.password.min-length", "12",
                    "keystone.security.password.require-uppercase", "true",
                    "keystone.security.password.require-lowercase", "true",
                    "keystone.security.password.require-digit", "true",
                    "keystone.security.password.require-special", "true",
                    "keystone.security.password.disallowed", "forbidden123!");
        }
    }
}
