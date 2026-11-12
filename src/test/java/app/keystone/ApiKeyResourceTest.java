package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import javax.sql.DataSource;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.*;

@QuarkusTest
class ApiKeyResourceTest {
    @Inject DataSource dataSource;

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
    void apiKeyWithReadScopeCanReadAuditButCannotUseAnUnlistedScope() {
        String admin = login();
        var issued = issue(admin, "audit-read", "audit:read");
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
    void rotatingAnApiKeyRevokesTheOldSecretAndKeepsTheApprovedScope() {
        String admin = login();
        var issued = issue(admin, "rotation", "audit:read");
        String oldKey = issued.path("data.apiKey");
        String oldId = issued.path("data.id");
        var rotated = given().auth().oauth2(admin)
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
        var issued = issue(admin, "expiry-redaction", "audit:read");
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
                .when().get("/logs/operationLogs?resource=api-key")
                .then().statusCode(200)
                .extract().asString();
        assertFalse(audit.contains(key), "API key audit logs must not contain the full secret");

        revoke(admin, id);
    }

    @Test
    void apiKeyCannotEnterHumanProfileOrPasswordPathsEvenWithMatchingScope() {
        String admin = login();
        var issued = issue(admin, "human-boundary", "profile:write");
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

    private static void revoke(String admin, String id) {
        given().auth().oauth2(admin)
                .when().delete("/v1/api-keys/" + id)
                .then().statusCode(200);
    }

    private void expire(String id) throws Exception {
        try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("UPDATE sys_api_key SET expires_at = CURRENT_TIMESTAMP - INTERVAL 1 SECOND WHERE id = ?")) {
            statement.setString(1, id);
            statement.executeUpdate();
        }
    }
}
