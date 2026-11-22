package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用真实 HTTP 和 MySQL 核验 API Key 轮换时的授权范围与记录状态。 */
@QuarkusTest
class ApiKeyScopeRotationHttpTest extends AuthTestFixture {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";
    private static final List<String> SUBJECT_PERMISSIONS = List.of(
            "api-key:create", "api-key:read", "api-key:rotate", "job:read", "operation-log:read");

    @Inject DataSource dataSource;

    private final List<TestSubject> subjects = new ArrayList<>();

    @Test
    void rotationPersistsOnlyCurrentScopesAndDoesNotExpandAfterPermissionRestore() throws Exception {
        TestSubject subject = createSubject();
        String token = login(subject.username());
        Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MICROS);
        IssuedKey old = issue(token, "scope-intersection", List.of("operation-log:read", "job:read"), expiresAt);

        changePermissions(subject, List.of("job:read"), List.of());
        token = login(subject.username());
        var rotated = given().auth().oauth2(token).contentType(JSON)
                .when().post("/v1/api-keys/" + old.id() + "/rotate")
                .then().statusCode(200)
                .body("data.scopes", contains("operation-log:read"))
                .extract();
        IssuedKey replacement = new IssuedKey(rotated.path("data.id"), rotated.path("data.apiKey"));

        KeyState oldState = keyState(old.id());
        KeyState replacementState = keyState(replacement.id());
        assertTrue(oldState.revokedAt() != null);
        assertEquals(replacement.id(), oldState.rotatedTo());
        assertEquals("job:read operation-log:read", oldState.scopes());
        assertNull(replacementState.revokedAt());
        assertEquals("operation-log:read", replacementState.scopes());
        assertEquals(oldState.expiresAt(), replacementState.expiresAt());

        given().header("Authorization", "ApiKey " + old.value())
                .when().get("/v1/operation-logs")
                .then().statusCode(401);
        given().header("Authorization", "ApiKey " + replacement.value())
                .when().get("/v1/operation-logs")
                .then().statusCode(200);

        changePermissions(subject, List.of(), List.of("job:read"));
        given().header("Authorization", "ApiKey " + replacement.value())
                .when().get("/v1/jobs")
                .then().statusCode(403);
        given().auth().oauth2(login(subject.username()))
                .when().get("/v1/api-keys")
                .then().statusCode(200)
                .body("data.find { it.id == '" + replacement.id() + "' }.scopes",
                        contains("operation-log:read"));
    }

    @Test
    void emptyPermissionIntersectionLeavesOldKeyUnchangedAndCreatesNoReplacement() throws Exception {
        TestSubject subject = createSubject();
        String token = login(subject.username());
        IssuedKey old = issue(token, "scope-empty", List.of("operation-log:read", "job:read"), null);
        long before = keyCount(subject.userId());

        changePermissions(subject, List.of("operation-log:read", "job:read"), List.of());
        token = login(subject.username());
        given().auth().oauth2(token).contentType(JSON)
                .when().post("/v1/api-keys/" + old.id() + "/rotate")
                .then().statusCode(422)
                .body("message", is("原授权范围已不可用，请重新配置权限。"))
                .body("error.code", is("api_key_scope_unavailable"));

        assertEquals(before, keyCount(subject.userId()));
        KeyState state = keyState(old.id());
        assertNull(state.revokedAt());
        assertNull(state.rotatedTo());
        assertEquals("job:read operation-log:read", state.scopes());
        assertNull(state.expiresAt());
    }

    /** 权限全部撤销后保留 API Key 认证状态，并把业务请求统一拒绝为 403。 */
    @Test
    void apiKeyWithAllApprovedScopesRevokedReturnsPermissionDeniedInsteadOfAuthenticationFailure() throws Exception {
        TestSubject subject = createSubject();
        String token = login(subject.username());
        IssuedKey key = issue(token, "scope-revoked", List.of("operation-log:read", "job:read"), null);

        given().header("Authorization", "ApiKey " + key.value())
                .when().get("/v1/operation-logs")
                .then().statusCode(200);

        changePermissions(subject, List.of("operation-log:read", "job:read"), List.of());
        given().header("Authorization", "ApiKey " + key.value())
                .when().get("/v1/operation-logs")
                .then().statusCode(403)
                .body("error.code", is("permission_denied"));
    }

    /** 建立只属于本测试的角色和用户，避免修改共享管理员权限。 */
    private TestSubject createSubject() throws Exception {
        String roleId = UUID.randomUUID().toString();
        String userId = UUID.randomUUID().toString();
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String roleCode = "API_KEY_ROTATE_" + suffix;
        String username = "api_key_rotate_" + suffix;
        try (Connection connection = dataSource.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'ALL')")) {
                statement.setString(1, roleId);
                statement.setString(2, roleCode);
                statement.setString(3, "API Key 范围轮换测试角色");
                statement.executeUpdate();
            }
            for (String permission : SUBJECT_PERMISSIONS) {
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
                statement.setString(4, "API Key 范围轮换测试用户");
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO sys_user_role (user_id, role_id) VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
                statement.setString(1, userId);
                statement.setString(2, roleId);
                statement.executeUpdate();
            }
        }
        TestSubject subject = new TestSubject(roleId, userId, username);
        subjects.add(subject);
        return subject;
    }

    /** 通过角色关联表撤销或恢复单项权限，并使旧的人类会话权限版本失效。 */
    private void changePermissions(TestSubject subject, List<String> revoke, List<String> grant) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            for (String code : revoke) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM sys_role_permission WHERE role_id = UUID_TO_BIN(?, 0) AND permission_id = (SELECT id FROM sys_permission WHERE code = ?)")) {
                    statement.setString(1, subject.roleId());
                    statement.setString(2, code);
                    assertEquals(1, statement.executeUpdate());
                }
            }
            for (String code : grant) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "INSERT INTO sys_role_permission (role_id, permission_id) SELECT UUID_TO_BIN(?, 0), id FROM sys_permission WHERE code = ?")) {
                    statement.setString(1, subject.roleId());
                    statement.setString(2, code);
                    assertEquals(1, statement.executeUpdate());
                }
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE sys_user SET permission_version = permission_version + 1 WHERE id = UUID_TO_BIN(?, 0)")) {
                statement.setString(1, subject.userId());
                assertEquals(1, statement.executeUpdate());
            }
        }
    }

    private String login(String username) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private IssuedKey issue(String token, String name, List<String> scopes, Instant expiresAt) {
        var body = new java.util.HashMap<String, Object>();
        body.put("name", name);
        body.put("scopes", scopes);
        if (expiresAt != null) body.put("expiresAt", expiresAt.toString());
        var response = given().auth().oauth2(token).contentType(JSON).body(body)
                .when().post("/v1/api-keys")
                .then().statusCode(201)
                .extract();
        return new IssuedKey(response.path("data.id"), response.path("data.apiKey"));
    }

    private KeyState keyState(String id) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT revoked_at, BIN_TO_UUID(rotated_to, 0), scopes, expires_at FROM sys_api_key WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, id);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                Timestamp revokedAt = result.getTimestamp(1);
                Timestamp expiresAt = result.getTimestamp(4);
                return new KeyState(revokedAt == null ? null : revokedAt.toInstant(), result.getString(2),
                        result.getString(3), expiresAt == null ? null : expiresAt.toInstant());
            }
        }
    }

    private long keyCount(String userId) throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM sys_api_key WHERE user_id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getLong(1);
            }
        }
    }

    @AfterEach
    void deleteSyntheticSubjects() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            for (TestSubject subject : subjects) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
                    statement.setString(1, subject.userId());
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM sys_service_subject WHERE code = ?")) {
                    statement.setString(1, "user:" + subject.userId());
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)")) {
                    statement.setString(1, subject.roleId());
                    statement.executeUpdate();
                }
            }
        }
    }

    private record IssuedKey(String id, String value) { }
    private record KeyState(Instant revokedAt, String rotatedTo, String scopes, Instant expiresAt) { }
    private record TestSubject(String roleId, String userId, String username) { }
}
