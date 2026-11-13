package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class MonitorAndLogTest extends AuthTestFixture {
    @Test
    void adminCanInspectSessionsAndAuditLogs() {
        String token = given().contentType(JSON).header("X-Forwarded-For", "192.0.2.10").body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        given().auth().oauth2(token).when().get("/monitor/onlineUsers").then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/monitor/serverInfo").then().statusCode(200).body("data.processors", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/monitor/cacheInfo").then().statusCode(200).body("data.provider", is("database"));
        given().auth().oauth2(token).when().get("/logs/loginLogs").then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).contentType(JSON).body("{\"action\":\"TEST\",\"resource\":\"monitor\",\"detail\":\"compatibility test\"}")
                .when().post("/logs/operationLogs").then().statusCode(200).body("data.recorded", is(true));
        given().auth().oauth2(token).when().get("/logs/operationLogs").then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
    }
}
