package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.hasItem;

@QuarkusTest
class JobResourceTest extends AuthTestFixture {
    @Test
    void annotatedJobCanBeDiscoveredAndTriggered() {
        String token = login();
        given().auth().oauth2(token)
                .when().get("/v1/jobs/invoke-targets")
                .then().statusCode(200).body("data.invokeTarget", hasItem("keystoneJob.heartbeat()"));

        String code = "test-job-" + System.nanoTime();
        String id = given().auth().oauth2(token).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"Test job\",\"cron\":\"0/30 * * * * ?\",\"invokeTarget\":\"keystoneJob.heartbeat()\",\"concurrent\":false}")
                .when().post("/v1/jobs")
                .then().statusCode(201).extract().path("data.id");

        given().auth().oauth2(token).when().post("/v1/jobs/" + id + "/run").then().statusCode(200).body("data.triggered", is(true));
        given().auth().oauth2(token).when().get("/v1/jobs/logs?jobId=" + id).then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().delete("/v1/jobs/" + id).then().statusCode(200);
    }

    private static String login() {
        return given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
