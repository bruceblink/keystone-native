package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

/** 验证安全运营报告使用真实 HTTP、权限和数据库查询，并拒绝无效时间范围。 */
@QuarkusTest
class SecurityOperationsReportTest extends AuthTestFixture {
    @Test
    void administratorCanReadRedactedOperationsReport() {
        String token = login();
        var issued = given().auth().oauth2(token).contentType(JSON)
                .body("{\"name\":\"report-rotation\",\"scopes\":[\"audit:read\"]}")
                .when().post("/v1/api-keys")
                .then().statusCode(201).extract();
        String secret = issued.path("data.apiKey");
        String id = issued.path("data.id");
        var rotated = given().auth().oauth2(token).contentType(JSON)
                .when().post("/v1/api-keys/" + id + "/rotate")
                .then().statusCode(200).extract();
        String replacementId = rotated.path("data.id");
        String replacementSecret = rotated.path("data.apiKey");
        given().header("Authorization", "ApiKey " + replacementSecret)
                .when().get("/v1/operation-logs")
                .then().statusCode(200);
        given().auth().oauth2(token)
                .when().get("/v1/monitor/security/report?horizonDays=30&page=1&size=20")
                .then().statusCode(200)
                .body("data.tenantScope", is("current"))
                .body("data.apiKeys.total", greaterThanOrEqualTo(0))
                .body("data.apiKeys.rotated", greaterThanOrEqualTo(1))
                .body("data.securityEvents.page", is(1))
                .body("data.securityEvents.size", is(20));
        String report = given().auth().oauth2(token)
                .when().get("/v1/monitor/security/report")
                .then().statusCode(200).extract().asString();
        assertFalse(report.contains(secret), "the report must not expose API key secrets");
        assertFalse(report.contains(replacementSecret), "the report must not expose rotated API key secrets");
        given().auth().oauth2(token).when().delete("/v1/api-keys/" + replacementId).then().statusCode(200);
    }

    @Test
    void reportRejectsInvalidTimeRangeAndPagination() {
        String token = login();
        given().auth().oauth2(token)
                .when().get("/v1/monitor/security/report?from=invalid")
                .then().statusCode(400)
                .body("error.code", is("validation_failed"));
        given().auth().oauth2(token)
                .when().get("/v1/monitor/security/report?page=0")
                .then().statusCode(400)
                .body("error.code", is("validation_failed"));
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
