package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;

/** 通过真实 HTTP 链路验证管理导出入口返回 XLSX 文件。 */
@QuarkusTest
class ExportResourceHttpTest extends AuthTestFixture {
    @Test
    void administratorCanExportRolePostAndAuditCollections() {
        String token = login("admin", "password");
        assertExcel(token, "/v1/roles/export");
        assertExcel(token, "/v1/posts/export");
        assertExcel(token, "/v1/login-logs/export");
        assertExcel(token, "/v1/operation-logs/export");
    }

    private static void assertExcel(String token, String path) {
        given().auth().oauth2(token)
                .when().get(path)
                .then().statusCode(200)
                .contentType(containsString("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
