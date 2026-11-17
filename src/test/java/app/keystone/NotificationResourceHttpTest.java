package app.keystone;

import app.keystone.identity.UuidValues;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用真实 HTTP 和 MySQL 验证站内通知的用户隔离、状态与事务边界。 */
@QuarkusTest
class NotificationResourceHttpTest extends AuthTestFixture {
    private static final Set<String> ITEM_FIELDS = Set.of(
            "id", "type", "title", "content", "createdAt", "readAt");

    @Inject DataSource dataSource;

    @Test
    void apiKeyEventsArePrivateAndReadIsIdempotent() {
        String admin = login("admin", "password");
        TestUser owner = createUser(admin, "notification_owner", "ADMIN");
        TestUser other = createUser(admin, "notification_other", "USER");
        String keyId = null;
        try {
            String ownerToken = login(owner.username(), "password");
            String otherToken = login(other.username(), "password");
            var issued = issueKey(ownerToken, "notification-read-boundary");
            String apiKey = issued.path("data.apiKey");
            String apiKeyPrefix = issued.path("data.prefix");
            keyId = issued.path("data.id");

            var list = given().auth().oauth2(ownerToken)
                    .when().get("/v1/notifications")
                    .then().statusCode(200)
                    .body("data.unreadCount", is(1))
                    .extract().response();
            Map<String, Object> inbox = list.jsonPath().getMap("data");
            assertEquals(Set.of("items", "unreadCount"), inbox.keySet());
            List<Map<String, Object>> items = list.jsonPath().getList("data.items");
            assertEquals(1, items.size());
            Map<String, Object> created = items.get(0);
            assertEquals(ITEM_FIELDS, created.keySet());
            assertEquals("api_key.created", created.get("type"));
            assertNull(created.get("readAt"));
            assertEquals('7', ((String) created.get("id")).charAt(14));
            assertFalse(list.asString().contains(apiKey));
            assertFalse(list.asString().contains(apiKeyPrefix));

            String notificationId = (String) created.get("id");
            Map<String, Object> detail = given().auth().oauth2(ownerToken)
                    .when().get("/v1/notifications/" + notificationId)
                    .then().statusCode(200)
                    .extract().path("data");
            assertEquals(created, detail);

            given().when().get("/v1/notifications").then().statusCode(401);
            given().header("Authorization", "ApiKey " + apiKey)
                    .when().get("/v1/notifications").then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().header("Authorization", "ApiKey " + apiKey)
                    .when().get("/v1/notifications/" + notificationId).then().statusCode(403);
            given().header("Authorization", "ApiKey " + apiKey)
                    .when().post("/v1/notifications/" + notificationId + "/read").then().statusCode(403);

            String unknownId = UuidValues.v7();
            var crossUserDetail = given().auth().oauth2(otherToken)
                    .when().get("/v1/notifications/" + notificationId)
                    .then().statusCode(404).extract().response();
            var missingDetail = given().auth().oauth2(otherToken)
                    .when().get("/v1/notifications/" + unknownId)
                    .then().statusCode(404).extract().response();
            assertEquals("resource_not_found", crossUserDetail.jsonPath().getString("error.code"));
            assertEquals(crossUserDetail.jsonPath().getString("error.code"), missingDetail.jsonPath().getString("error.code"));
            assertEquals(crossUserDetail.jsonPath().getString("message"), missingDetail.jsonPath().getString("message"));

            var crossUserRead = given().auth().oauth2(otherToken)
                    .when().post("/v1/notifications/" + notificationId + "/read")
                    .then().statusCode(404).extract().response();
            var missingRead = given().auth().oauth2(otherToken)
                    .when().post("/v1/notifications/" + unknownId + "/read")
                    .then().statusCode(404).extract().response();
            assertEquals("resource_not_found", crossUserRead.jsonPath().getString("error.code"));
            assertEquals(crossUserRead.jsonPath().getString("error.code"), missingRead.jsonPath().getString("error.code"));
            assertEquals(crossUserRead.jsonPath().getString("message"), missingRead.jsonPath().getString("message"));
            given().auth().oauth2(ownerToken).when().get("/v1/notifications")
                    .then().statusCode(200).body("data.unreadCount", is(1));
            given().auth().oauth2(otherToken).when().get("/v1/notifications")
                    .then().statusCode(200).body("data.items", org.hamcrest.Matchers.empty())
                    .body("data.unreadCount", is(0));

            Map<String, Object> firstRead = given().auth().oauth2(ownerToken)
                    .when().post("/v1/notifications/" + notificationId + "/read")
                    .then().statusCode(200).extract().path("data");
            assertEquals(ITEM_FIELDS, firstRead.keySet());
            String readAt = (String) firstRead.get("readAt");
            assertNotNull(readAt);
            Map<String, Object> detailAfterRead = given().auth().oauth2(ownerToken)
                    .when().get("/v1/notifications/" + notificationId)
                    .then().statusCode(200).extract().path("data");
            Map<String, Object> repeatedRead = given().auth().oauth2(ownerToken)
                    .when().post("/v1/notifications/" + notificationId + "/read")
                    .then().statusCode(200).extract().path("data");
            assertEquals(firstRead, detailAfterRead);
            assertEquals(firstRead, repeatedRead);
            given().auth().oauth2(ownerToken).when().get("/v1/notifications")
                    .then().statusCode(200).body("data.unreadCount", is(0));

            var rotated = given().auth().oauth2(ownerToken)
                    .contentType(JSON).when().post("/v1/api-keys/" + keyId + "/rotate")
                    .then().statusCode(200).extract();
            String replacementId = rotated.path("data.id");
            String replacementSecret = rotated.path("data.apiKey");
            given().auth().oauth2(ownerToken).when().delete("/v1/api-keys/" + replacementId)
                    .then().statusCode(200);
            given().auth().oauth2(ownerToken).when().delete("/v1/api-keys/" + replacementId)
                    .then().statusCode(200);

            var finalList = given().auth().oauth2(ownerToken)
                    .when().get("/v1/notifications").then().statusCode(200)
                    .body("data.items", org.hamcrest.Matchers.hasSize(3))
                    .body("data.unreadCount", is(2))
                    .extract().response();
            List<Map<String, Object>> finalItems = finalList.jsonPath().getList("data.items");
            assertEquals(Set.of("api_key.created", "api_key.rotated", "api_key.revoked"),
                    finalItems.stream().map(item -> item.get("type").toString()).collect(java.util.stream.Collectors.toSet()));
            assertTrue(finalItems.stream().allMatch(item -> ITEM_FIELDS.equals(item.keySet())));
            assertFalse(finalList.asString().contains(apiKey));
            assertFalse(finalList.asString().contains(replacementSecret));
            assertFalse(finalList.asString().contains(apiKeyPrefix));
            assertNotNull(Instant.parse(readAt));
        } finally {
            deleteUser(admin, owner.id());
            deleteUser(admin, other.id());
        }
    }

    @Test
    void inboxReturnsFiftyNewestButCountsEveryUnreadNotification() throws Exception {
        String admin = login("admin", "password");
        TestUser owner = createUser(admin, "notification_limit", "USER");
        try {
            String token = login(owner.username(), "password");
            Instant newest = Instant.now().minusSeconds(1);
            String newestId = null;
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement(
                         "INSERT INTO sys_notification "
                                 + "(id, recipient_user_id, type, title, content, created_at, read_at) "
                                 + "VALUES (?, ?, 'test.manual', '测试通知', '分页验收数据', ?, ?)")) {
                for (int index = 0; index < 53; index++) {
                    String id = UuidValues.v7();
                    if (index == 0) newestId = id;
                    statement.setBytes(1, UuidValues.toBytes(id));
                    statement.setBytes(2, UuidValues.toBytes(owner.id()));
                    statement.setTimestamp(3, Timestamp.from(newest.minusSeconds(index)));
                    if (index < 2) statement.setTimestamp(4, Timestamp.from(newest));
                    else statement.setNull(4, Types.TIMESTAMP);
                    statement.addBatch();
                }
                statement.executeBatch();
            }

            var response = given().auth().oauth2(token)
                    .when().get("/v1/notifications")
                    .then().statusCode(200)
                    .body("data.items", org.hamcrest.Matchers.hasSize(50))
                    .body("data.unreadCount", is(51))
                    .extract().response();
            List<Map<String, Object>> items = response.jsonPath().getList("data.items");
            assertEquals(newestId, items.get(0).get("id"));
            assertEquals(ITEM_FIELDS, items.get(0).keySet());
            assertNotNull(items.get(0).get("readAt"));
            assertNull(items.get(2).get("readAt"));
            assertTrue(Instant.parse(items.get(0).get("createdAt").toString())
                    .isAfter(Instant.parse(items.get(49).get("createdAt").toString())));
        } finally {
            deleteUser(admin, owner.id());
        }
    }

    @Test
    void notificationMigrationCanBeReappliedAfterTableCreation() throws Exception {
        String migration;
        try (InputStream input = getClass().getClassLoader()
                .getResourceAsStream("db/migration/V61__user_notifications.sql")) {
            assertNotNull(input);
            migration = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replaceFirst("(?m)^\\s*--.*$", "")
                    .trim();
        }
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute(migration);
            statement.execute(migration);
            try (ResultSet columns = connection.getMetaData().getColumns(
                    connection.getCatalog(), null, "sys_notification", null)) {
                Set<String> names = new LinkedHashSet<>();
                while (columns.next()) names.add(columns.getString("COLUMN_NAME"));
                assertEquals(Set.of("id", "recipient_user_id", "type", "title", "content", "created_at", "read_at"), names);
            }
        }
    }

    @Test
    void keyMutationRollsBackWhenItsNotificationCannotBeStored() throws Exception {
        String admin = login("admin", "password");
        TestUser owner = createUser(admin, "notification_transaction", "ADMIN");
        String token = login(owner.username(), "password");
        try {
            String issueName = "notification-rollback-create-" + System.nanoTime();
            String constraint = createNotificationFailureConstraint(owner.id(), "api_key.created");
            try {
                var failedIssue = given().auth().oauth2(token).contentType(JSON)
                        .body("{\"name\":\"" + issueName + "\",\"scopes\":[\"api-key:read\"]}")
                        .when().post("/v1/api-keys").then().extract().response();
                assertServerFailure(failedIssue.statusCode());
                assertEquals(0, keyCount(owner.id(), issueName));
                assertEquals(0, notificationCount(owner.id()));
            } finally {
                dropNotificationFailureConstraint(constraint);
            }

            var rotationKey = issueKey(token, "notification-rollback-rotate");
            String rotationId = rotationKey.path("data.id");
            String rotationName = rotationKey.path("data.name");
            String rotatedConstraint = createNotificationFailureConstraint(owner.id(), "api_key.rotated");
            try {
                int notificationBaseline = notificationCount(owner.id());
                var failedRotation = given().auth().oauth2(token).contentType(JSON)
                        .when().post("/v1/api-keys/" + rotationId + "/rotate").then().extract().response();
                assertServerFailure(failedRotation.statusCode());
                assertFalse(keyIsRevoked(owner.id(), rotationId));
                assertEquals(1, keyCount(owner.id(), rotationName));
                assertEquals(notificationBaseline, notificationCount(owner.id()));

                dropNotificationFailureConstraint(rotatedConstraint);
                rotatedConstraint = null;
                rotatedConstraint = createNotificationFailureConstraint(owner.id(), "api_key.revoked");
                var failedRevoke = given().auth().oauth2(token)
                        .when().delete("/v1/api-keys/" + rotationId).then().extract().response();
                assertServerFailure(failedRevoke.statusCode());
                assertFalse(keyIsRevoked(owner.id(), rotationId));
                assertEquals(notificationBaseline, notificationCount(owner.id()));
            } finally {
                if (rotatedConstraint != null) dropNotificationFailureConstraint(rotatedConstraint);
            }
        } finally {
            deleteUser(admin, owner.id());
        }
    }

    private static TestUser createUser(String admin, String prefix, String role) {
        String username = prefix + "_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\","
                        + "\"displayName\":\"Notification test\",\"roleCodes\":[\"" + role + "\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        return new TestUser(id, username);
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password
                        + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private static io.restassured.response.ExtractableResponse<io.restassured.response.Response> issueKey(
            String token, String namePrefix) {
        return given().auth().oauth2(token).contentType(JSON)
                .body("{\"name\":\"" + namePrefix + "-" + System.nanoTime()
                        + "\",\"scopes\":[\"api-key:read\"]}")
                .when().post("/v1/api-keys").then().statusCode(201).extract();
    }

    private static void deleteUser(String admin, String userId) {
        given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
    }

    private static void assertServerFailure(int statusCode) {
        assertTrue(statusCode >= 500 && statusCode < 600, "persistence failure must fail the operation");
    }

    /** 给指定收件人和事件类型加临时约束，制造真实数据库写入失败并检查事务回滚。 */
    private String createNotificationFailureConstraint(String userId, String eventType) throws SQLException {
        String name = "chk_notification_failure_" + UUID.randomUUID().toString().replace("-", "");
        String userHex = java.util.HexFormat.of().formatHex(UuidValues.toBytes(userId));
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE sys_notification ADD CONSTRAINT `" + name + "` CHECK "
                    + "(recipient_user_id <> X'" + userHex + "' OR type <> '" + eventType + "')");
        }
        return name;
    }

    private void dropNotificationFailureConstraint(String name) {
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE sys_notification DROP CHECK `" + name + "`");
        } catch (SQLException error) {
            throw new IllegalStateException("could not remove notification test constraint", error);
        }
    }

    private long keyCount(String userId, String name) throws SQLException {
        try (Connection connection = dataSource.getConnection(); PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM sys_api_key WHERE user_id = ? AND name = ?")) {
            statement.setBytes(1, UuidValues.toBytes(userId));
            statement.setString(2, name);
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getLong(1);
            }
        }
    }

    private boolean keyIsRevoked(String userId, String keyId) throws SQLException {
        try (Connection connection = dataSource.getConnection(); PreparedStatement statement = connection.prepareStatement(
                "SELECT revoked_at FROM sys_api_key WHERE user_id = ? AND id = ?")) {
            statement.setBytes(1, UuidValues.toBytes(userId));
            statement.setBytes(2, UuidValues.toBytes(keyId));
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getTimestamp(1) != null;
            }
        }
    }

    private int notificationCount(String userId) throws SQLException {
        try (Connection connection = dataSource.getConnection(); PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM sys_notification WHERE recipient_user_id = ?")) {
            statement.setBytes(1, UuidValues.toBytes(userId));
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private record TestUser(String id, String username) {
    }
}
