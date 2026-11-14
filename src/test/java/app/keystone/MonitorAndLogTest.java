package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

@QuarkusTest
class MonitorAndLogTest extends AuthTestFixture {
    @Test
    void adminCanInspectMonitorData() {
        String token = given().contentType(JSON).header("X-Forwarded-For", "192.0.2.10").body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        given().auth().oauth2(token).when().get("/v1/monitor/onlineUsers").then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/v1/monitor/serverInfo").then().statusCode(200).body("data.processors", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().get("/v1/monitor/cacheInfo").then().statusCode(200).body("data.provider", org.hamcrest.Matchers.is("database"));
        given().auth().oauth2(token).when().get("/v1/monitor/security").then().statusCode(200).body("data.loginFailures", greaterThanOrEqualTo(0));
    }
}
