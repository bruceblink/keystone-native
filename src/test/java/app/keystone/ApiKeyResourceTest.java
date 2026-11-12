package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.*;

@QuarkusTest
class ApiKeyResourceTest {
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
}
