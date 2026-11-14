package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class MonitorAndLogTest extends AuthTestFixture {
    @Test
    void adminCanInspectMonitorData() {
        String token = given().contentType(JSON).header("X-Forwarded-For", "192.0.2.10").body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        given().auth().oauth2(token).when().get("/v1/monitor/onlineUsers").then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/v1/monitor/serverInfo").then().statusCode(200).body("data.processors", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/v1/monitor/cacheInfo").then().statusCode(200).body("data.provider", org.hamcrest.Matchers.is("database"));
        given().auth().oauth2(token).when().get("/v1/login-logs?size=10").then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/v1/monitor/security").then().statusCode(200).body("data.loginFailures", greaterThanOrEqualTo(0));
    }

    @Test
    void onlineSessionUsesLoginSessionIdAndRevocationInvalidatesTheToken() {
        var login = given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        String accessToken = login.path("data.accessToken");
        String sessionId = login.path("data.sessionId");

        var online = given().auth().oauth2(accessToken)
                .when().get("/v1/monitor/onlineUsers")
                .then().statusCode(200).extract();
        java.util.List<String> sessionIds = online.path("data.items.sessionId");
        assertTrue(sessionIds.contains(sessionId));

        given().auth().oauth2(accessToken)
                .when().delete("/v1/monitor/onlineUser/" + sessionId)
                .then().statusCode(200);
        given().auth().oauth2(accessToken)
                .when().get("/v1/profile")
                .then().statusCode(401);

        String replacement = given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        var remaining = given().auth().oauth2(replacement)
                .when().get("/v1/monitor/onlineUsers")
                .then().statusCode(200).extract();
        java.util.List<String> remainingSessionIds = remaining.path("data.items.sessionId");
        assertFalse(remainingSessionIds.contains(sessionId));
    }
}
