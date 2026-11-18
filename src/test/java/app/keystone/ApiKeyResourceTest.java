package app.keystone;

import app.keystone.identity.UuidValues;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Instant;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.*;

@QuarkusTest
class ApiKeyResourceTest extends AuthTestFixture {
    @Inject DataSource dataSource;

    /** 校验名称和到期时间错误分别返回唯一业务码，且保持 HTTP 422。 */
    @Test
    void issueReturnsUniqueCodesForNameAndExpiryValidation() {
        String admin = login();
        assertIssueError(admin, "{\"scopes\":[\"api-key:read\"]}", "api_key_name_invalid");
        assertIssueError(admin, "{\"name\":\"   \",\"scopes\":[\"api-key:read\"]}", "api_key_name_invalid");
        assertIssueError(admin, "{\"name\":\"" + "x".repeat(129)
                + "\",\"scopes\":[\"api-key:read\"]}", "api_key_name_invalid");
        assertIssueError(admin, "{\"name\":\"bad-expiry\",\"scopes\":[\"api-key:read\"],"
                + "\"expiresAt\":\"not-a-date\"}", "api_key_expiry_invalid");
        assertIssueError(admin, "{\"name\":\"typed-expiry\",\"scopes\":[\"api-key:read\"],"
                + "\"expiresAt\":7}", "api_key_expiry_invalid");
        assertIssueError(admin, "{\"name\":\"expired\",\"scopes\":[\"api-key:read\"],"
                + "\"expiresAt\":\"" + Instant.now().minusSeconds(60) + "\"}",
                "api_key_expiry_out_of_range");
        assertIssueError(admin, "{\"name\":\"too-far\",\"scopes\":[\"api-key:read\"],"
                + "\"expiresAt\":\"" + Instant.now().plusSeconds(91L * 24 * 3600) + "\"}",
                "api_key_expiry_out_of_range");

        String valid = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"valid-expiry\",\"scopes\":[\"api-key:read\"],"
                        + "\"expiresAt\":\"" + Instant.now().plusSeconds(30L * 24 * 3600) + "\"}")
                .when().post("/v1/api-keys").then().statusCode(201)
                .extract().path("data.id");
        revoke(admin, valid);
    }

    /** 表情和组合字符按数据库使用的 Unicode 码点数校验名称上限。 */
    @Test
    void issueNameLimitFollowsDatabaseUnicodeCodePoints() {
        String admin = login();
        for (String name : new String[]{"😀".repeat(128), "e\u0301".repeat(64)}) {
            String id = given().auth().oauth2(admin).contentType(JSON)
                    .body(java.util.Map.of("name", name, "scopes", java.util.List.of("api-key:read")))
                    .when().post("/v1/api-keys").then().statusCode(201)
                    .body("data.name", is(name)).extract().path("data.id");
            revoke(admin, id);
        }
        for (String name : new String[]{"😀".repeat(129), "e\u0301".repeat(64) + "e"}) {
            given().auth().oauth2(admin).contentType(JSON)
                    .body(java.util.Map.of("name", name, "scopes", java.util.List.of("api-key:read")))
                    .when().post("/v1/api-keys").then().statusCode(422)
                    .body("error.code", is("api_key_name_invalid"));
        }
    }

    @Test
    void adminCanIssueAndUseAndRevokeAnApiKey() {
        String admin = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        var issued = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"ci\",\"scopes\":[\"api-key:read\"]}")
                .when().post("/v1/api-keys").then().statusCode(201)
                .body("data.apiKey", startsWith("ks_live_"))
                .extract();
        String key = issued.path("data.apiKey");
        String id = issued.path("data.id");
        given().header("Authorization", "ApiKey " + key).when().get("/v1/operation-logs").then().statusCode(403);
        given().header("Authorization", "ApiKey invalid").when().get("/v1/operation-logs").then().statusCode(401);
        given().auth().oauth2(admin).when().delete("/v1/api-keys/" + id).then().statusCode(200);
        given().header("Authorization", "ApiKey " + key).when().get("/v1/operation-logs").then().statusCode(401);
    }

    @Test
    void invalidApiKeysFromOneSourceAreBlockedAfterTheConfiguredFailureWindow() throws Exception {
        clearApiKeyRateLimits();
        String guessedValue = "ks_live_guess_" + System.nanoTime();
        try {
            for (int attempt = 0; attempt < 20; attempt++) {
                given().header("Authorization", "ApiKey " + guessedValue)
                        .when().get("/v1/operation-logs")
                        .then().statusCode(401);
            }
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement(
                         "SELECT COUNT(*) FROM sys_api_key_rate_limit WHERE blocked_until > CURRENT_TIMESTAMP AND attempt_count >= 20")) {
                try (var result = statement.executeQuery()) {
                    assertTrue(result.next());
                    assertTrue(result.getInt(1) >= 1, "repeated invalid API keys must create a blocked rate-limit bucket");
                }
            }
        } finally {
            clearApiKeyRateLimits();
        }
    }

    @Test
    void apiKeyWithOperationLogReadScopeCanReadOperationLogsButCannotUseAnUnlistedScope() {
        String admin = login();
        var issued = issue(admin, "operation-log-read", "operation-log:read");
        String key = issued.path("data.apiKey");
        String id = issued.path("data.id");

        given().header("Authorization", "ApiKey " + key)
                .when().get("/v1/operation-logs")
                .then().statusCode(200);
        given().header("Authorization", "ApiKey " + key)
                .when().get("/v1/api-keys")
                .then().statusCode(403);

        revoke(admin, id);
    }

    @Test
    void apiKeyListSupportsServerPaginationKeywordAndStatusFilters() {
        String admin = login();
        String marker = "page-key-" + System.nanoTime();
        var first = issue(admin, marker + "-a", "api-key:read");
        var second = issue(admin, marker + "-b", "api-key:read");
        String firstId = first.path("data.id");
        String secondId = second.path("data.id");

        given().auth().oauth2(admin)
                .when().get("/v1/api-keys?page=1&size=1&keyword=" + marker + "&status=active")
                .then().statusCode(200)
                .body("data.page", equalTo(1))
                .body("data.size", equalTo(1))
                .body("data.total", equalTo(2))
                .body("data.items", hasSize(1))
                .body("data.items[0].name", startsWith(marker));

        revoke(admin, firstId);
        given().auth().oauth2(admin)
                .when().get("/v1/api-keys?page=1&size=20&keyword=" + marker + "&status=revoked")
                .then().statusCode(200)
                .body("data.total", equalTo(1))
                .body("data.items[0].id", equalTo(firstId));

        revoke(admin, secondId);
    }

    @Test
    void rotatingAnApiKeyRevokesTheOldSecretAndKeepsTheApprovedScope() {
        String admin = login();
        var issued = issue(admin, "rotation", "operation-log:read");
        String oldKey = issued.path("data.apiKey");
        String oldId = issued.path("data.id");
        var rotated = given().auth().oauth2(admin).contentType(JSON)
                .when().post("/v1/api-keys/" + oldId + "/rotate")
                .then().statusCode(200)
                .body("data.apiKey", startsWith("ks_live_"))
                .extract();
        String newKey = rotated.path("data.apiKey");
        String newId = rotated.path("data.id");

        given().header("Authorization", "ApiKey " + oldKey)
                .when().get("/v1/operation-logs")
                .then().statusCode(401);
        given().header("Authorization", "ApiKey " + newKey)
                .when().get("/v1/operation-logs")
                .then().statusCode(200);

        revoke(admin, newId);
    }

    @Test
    void expiredApiKeyIsRejectedAndItsSecretIsNeverReturnedByMetadataOrAudit() throws Exception {
        String admin = login();
        var issued = issue(admin, "expiry-redaction", "operation-log:read");
        String key = issued.path("data.apiKey");
        String id = issued.path("data.id");
        String prefix = issued.path("data.prefix");

        expire(id);
        given().header("Authorization", "ApiKey " + key)
                .when().get("/v1/operation-logs")
                .then().statusCode(401);

        String metadata = given().auth().oauth2(admin)
                .when().get("/v1/api-keys")
                .then().statusCode(200)
                .extract().asString();
        assertFalse(metadata.contains(key), "API key metadata must not contain the full secret");
        assertTrue(metadata.contains(prefix), "API key metadata should retain the public prefix");

        String audit = given().auth().oauth2(admin)
                .when().get("/v1/operation-logs?resource=api-key")
                .then().statusCode(200)
                .extract().asString();
        assertFalse(audit.contains(key), "API key audit logs must not contain the full secret");

        revoke(admin, id);
    }

    /** 到期密钥不属于有效列表，轮换失败后不能新增替代密钥或撤销原记录。 */
    @Test
    void expiredKeyIsExcludedFromActiveAndCannotRotate() throws Exception {
        String admin = login();
        String marker = "expired-filter-" + System.nanoTime();
        String id = issue(admin, marker, "api-key:read").path("data.id");
        expire(id);

        given().auth().oauth2(admin)
                .when().get("/v1/api-keys?page=1&size=20&keyword=" + marker + "&status=active")
                .then().statusCode(200).body("data.total", equalTo(0));
        given().auth().oauth2(admin)
                .when().get("/v1/api-keys?page=1&size=20&keyword=" + marker + "&status=all")
                .then().statusCode(200).body("data.total", equalTo(1)).body("data.items[0].revokedAt", nullValue());
        given().auth().oauth2(admin).contentType(JSON)
                .when().post("/v1/api-keys/" + id + "/rotate")
                .then().statusCode(409).body("error.code", equalTo("api_key_expired"));
        given().auth().oauth2(admin)
                .when().get("/v1/api-keys?page=1&size=20&keyword=" + marker + "&status=all")
                .then().statusCode(200).body("data.total", equalTo(1)).body("data.items[0].revokedAt", nullValue());
        revoke(admin, id);
    }

    @Test
    void apiKeyCannotEnterHumanProfileOrPasswordPathsEvenWithMatchingScope() {
        String admin = login();
        var issued = issue(admin, "human-boundary", "user:update");
        String key = issued.path("data.apiKey");
        String id = issued.path("data.id");

        given().header("Authorization", "ApiKey " + key)
                .when().get("/v1/profile")
                .then().statusCode(403);
        given().header("Authorization", "ApiKey " + key).contentType(JSON)
                .body("{\"password\":\"another-password\"}")
                .when().put("/v1/profile/password")
                .then().statusCode(403);

        revoke(admin, id);
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private static io.restassured.response.ExtractableResponse<io.restassured.response.Response> issue(String admin, String name, String scope) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"" + name + "-" + System.nanoTime() + "\",\"scopes\":[\"" + scope + "\"]}")
                .when().post("/v1/api-keys")
                .then().statusCode(201)
                .body("data.apiKey", startsWith("ks_live_"))
                .extract();
    }

    /** 用真实 HTTP 签发请求核对校验失败的状态和业务码。 */
    private static void assertIssueError(String admin, String body, String errorCode) {
        given().auth().oauth2(admin).contentType(JSON).body(body)
                .when().post("/v1/api-keys")
                .then().statusCode(422).body("error.code", is(errorCode));
    }

    private void clearApiKeyRateLimits() throws Exception {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("DELETE FROM sys_api_key_rate_limit")) {
            statement.executeUpdate();
        }
    }

    private static void revoke(String admin, String id) {
        given().auth().oauth2(admin)
                .when().delete("/v1/api-keys/" + id)
                .then().statusCode(200);
    }

    private void expire(String id) throws Exception {
        try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("UPDATE sys_api_key SET expires_at = CURRENT_TIMESTAMP - INTERVAL 1 SECOND WHERE id = ?")) {
            statement.setBytes(1, UuidValues.toBytes(id));
            statement.executeUpdate();
        }
    }
}
