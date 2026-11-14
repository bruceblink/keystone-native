package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipInputStream;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 通过真实 HTTP 链路验证管理导出入口返回 XLSX 文件。 */
@QuarkusTest
class ExportResourceHttpTest extends AuthTestFixture {
    @Test
    void administratorCanExportRolePostAndAuditCollections() {
        String token = login("admin", "password");
        assertExcel(token, "/v1/roles/export", "roles.xlsx");
        assertExcel(token, "/v1/posts/export", "posts.xlsx");
        assertExcel(token, "/v1/login-logs/export", "login-logs.xlsx");
        assertExcel(token, "/v1/operation-logs/export", "operation-logs.xlsx");
    }

    /** 验证响应是可读取的 Open XML 工作簿，并且下载文件名保持 xlsx 约定。 */
    private static void assertExcel(String token, String path, String filename) {
        var response = given().auth().oauth2(token)
                .when().get(path)
                .then().statusCode(200)
                .contentType(containsString("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .extract().response();
        assertTrue(response.header("Content-Disposition").contains("filename=" + filename));
        Set<String> entries = new HashSet<>();
        try (var zip = new ZipInputStream(new ByteArrayInputStream(response.asByteArray()))) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                entries.add(entry.getName());
            }
        } catch (java.io.IOException e) {
            throw new AssertionError("export response is not a readable XLSX workbook", e);
        }
        assertTrue(entries.contains("[Content_Types].xml"));
        assertTrue(entries.contains("xl/workbook.xml"));
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
