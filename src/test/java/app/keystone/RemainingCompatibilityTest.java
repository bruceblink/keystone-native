package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class RemainingCompatibilityTest extends AuthTestFixture {
    @Test
    void rootMenuJobProfileAndExportRoutesAreAvailable() {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        given().when().get("/").then().statusCode(200).body("data.status", is("UP"));
        given().auth().oauth2(token).when().get("/system/user/profile").then().statusCode(200);
        given().auth().oauth2(token).when().get("/system/users/excelTemplate").then().statusCode(200).header("Content-Disposition", containsString("users-template.csv"));
        given().auth().oauth2(token).when().post("/system/role/export").then().statusCode(200).header("Content-Disposition", containsString("roles.csv"));
        given().auth().oauth2(token).when().get("/logs/operationLogs/excel").then().statusCode(200).header("Content-Disposition", containsString("operation-logs.csv"));

        int menuId = given().auth().oauth2(token).contentType(JSON)
                .body("{\"code\":\"compat-menu-" + System.nanoTime() + "\",\"name\":\"Compatibility Menu\",\"path\":\"/compat\",\"menuType\":\"MENU\"}")
                .when().post("/system/menus").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(token).when().delete("/system/menus/" + menuId).then().statusCode(200);

        int jobId = given().auth().oauth2(token).contentType(JSON)
                .body("{\"code\":\"compat-job-" + System.nanoTime() + "\",\"name\":\"Compatibility Job\",\"cron\":\"0/30 * * * * ?\",\"invokeTarget\":\"keystoneJob.heartbeat()\"}")
                .when().post("/system/jobs").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(token).when().post("/system/jobs/" + jobId + "/run").then().statusCode(200);
        given().auth().oauth2(token).when().delete("/system/jobs?jobIds=" + jobId).then().statusCode(200);
    }
}
