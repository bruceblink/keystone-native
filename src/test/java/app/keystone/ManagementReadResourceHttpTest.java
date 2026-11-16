package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.notNullValue;

/** 通过真实 HTTP 和 MySQL 验证常用管理查询入口的响应边界。 */
@QuarkusTest
class ManagementReadResourceHttpTest extends AuthTestFixture {
    @Test
    void adminCanReadConfigDictionaryAndNoticeQueries() {
        String token = login();

        assertDataList(token, "/v1/configs");
        assertDataList(token, "/v1/dictionaries");
        assertDataList(token, "/v1/notices/manage");
    }

    @Test
    void adminCanReadPagedConfigsWithTotal() {
        String token = login();

        given().auth().oauth2(token)
                .when().get("/v1/configs?page=1&size=20&keyword=system")
                .then().statusCode(200)
                .body("success", org.hamcrest.Matchers.is(true))
                .body("data.items", notNullValue())
                .body("data.page", org.hamcrest.Matchers.is(1))
                .body("data.size", org.hamcrest.Matchers.is(20))
                .body("data.total", org.hamcrest.Matchers.greaterThanOrEqualTo(0));
    }

    @Test
    void adminCanReadPagedNoticesWithKeywordAndStatus() {
        String token = login();
        String title = "分页公告-" + System.nanoTime();
        String noticeId = null;
        try {
            noticeId = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"title\":\"" + title + "\",\"content\":\"分页内容\",\"noticeType\":\"NOTICE\"}")
                    .when().post("/v1/notices")
                    .then().statusCode(201)
                    .extract().path("data.id");

            given().auth().oauth2(token)
                    .when().get("/v1/notices/manage?page=1&size=1&keyword=" + title + "&status=unpublished")
                    .then().statusCode(200)
                    .body("success", org.hamcrest.Matchers.is(true))
                    .body("data.items", org.hamcrest.Matchers.hasSize(1))
                    .body("data.page", org.hamcrest.Matchers.is(1))
                    .body("data.size", org.hamcrest.Matchers.is(1))
                    .body("data.total", org.hamcrest.Matchers.is(1));
        } finally {
            if (noticeId != null) given().auth().oauth2(token).when().delete("/v1/notices/" + noticeId);
        }
    }

    @Test
    void adminCanReadDictionaryItemsAfterCreatingAType() {
        String token = login();
        String typeCode = "http_scope_" + System.nanoTime();
        String itemId = null;
        try {
            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"code\":\"" + typeCode + "\",\"name\":\"HTTP scope type\",\"enabled\":true}")
                    .when().post("/v1/dictionaries")
                    .then().statusCode(201);

            itemId = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"value\":\"enabled\",\"label\":\"Enabled\",\"sortOrder\":1,\"enabled\":true}")
                    .when().post("/v1/dictionaries/" + typeCode + "/items")
                    .then().statusCode(201)
                    .extract().path("data.id");

            given().auth().oauth2(token)
                    .when().get("/v1/dictionaries/" + typeCode + "/items")
                    .then().statusCode(200)
                    .body("data[0].id", org.hamcrest.Matchers.is(itemId));
        } finally {
            if (itemId != null) {
                given().auth().oauth2(token).when().delete("/v1/dictionaries/items/" + itemId);
            }
            given().auth().oauth2(token).when().delete("/v1/dictionaries/types/" + typeCode);
        }
    }

    private static void assertDataList(String token, String path) {
        given().auth().oauth2(token)
                .when().get(path)
                .then().statusCode(200)
                .body("success", org.hamcrest.Matchers.is(true))
                .body("data", notNullValue());
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
