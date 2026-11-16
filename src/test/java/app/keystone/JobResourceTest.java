package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;

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

        given().auth().oauth2(token).when().post("/v1/jobs/" + id + "/trigger").then().statusCode(200).body("data.triggered", is(true));
        given().auth().oauth2(token).when().get("/v1/jobs/logs?jobId=" + id).then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(token).when().delete("/v1/jobs/" + id).then().statusCode(200);
    }

    @Test
    void listSupportsServerPaginationAndFiltersWhileKeepingLegacyArray() {
        String token = login();
        Object legacy = given().auth().oauth2(token)
                .when().get("/v1/jobs")
                .then().statusCode(200).extract().path("data");
        org.junit.jupiter.api.Assertions.assertInstanceOf(java.util.List.class, legacy);

        java.util.List<String> ids = new java.util.ArrayList<>();
        String marker = "page-job-" + System.nanoTime();
        for (int index = 1; index <= 3; index++) {
            String id = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"code\":\"" + marker + "-" + index + "\",\"name\":\"" + marker + "\",\"group\":\"PAGED\",\"cron\":\"0/30 * * * * ?\",\"invokeTarget\":\"keystoneJob.heartbeat()\",\"enabled\":" + (index != 3) + "}")
                    .when().post("/v1/jobs")
                    .then().statusCode(201).extract().path("data.id");
            ids.add(id);
        }

        given().auth().oauth2(token)
                .when().get("/v1/jobs?page=2&size=2&keyword=" + marker)
                .then().statusCode(200)
                .body("data.page", is(2))
                .body("data.size", is(2))
                .body("data.total", is(3))
                .body("data.items", hasSize(1));

        given().auth().oauth2(token)
                .when().get("/v1/jobs?page=1&size=20&status=disabled&keyword=" + marker)
                .then().statusCode(200)
                .body("data.total", is(1))
                .body("data.items", hasSize(1));

        given().auth().oauth2(token)
                .when().delete("/v1/jobs?jobIds=" + String.join(",", ids))
                .then().statusCode(200);
    }

    private static String login() {
        return given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
