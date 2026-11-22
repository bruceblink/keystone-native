package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 和隔离 MySQL 验证公告类型的 Unicode 码点边界和无副作用失败。 */
@QuarkusTest
class NoticeTypeLengthResourceHttpTest extends AuthTestFixture {
    @Test
    void acceptsThirtyTwoCodePointsAndRejectsLongerCreateAndUpdate() {
        String token = login();
        List<String> noticeIds = new ArrayList<>();
        try {
            String ascii32 = "A".repeat(32);
            String emoji32 = "😀".repeat(32);
            String combining32 = "e\u0301".repeat(16);
            String[] validTypes = {ascii32, emoji32, combining32};
            for (String noticeType : validTypes) {
                String title = uniqueTitle();
                String id = createNotice(token, title, noticeType);
                noticeIds.add(id);
                assertNoticeType(token, title, noticeType);
            }

            String ascii33 = "A".repeat(33);
            String emoji33 = "😀".repeat(33);
            String combining34 = "e\u0301".repeat(17);
            for (String noticeType : new String[]{ascii33, emoji33, combining34}) {
                rejectCreateWithoutSideEffect(token, uniqueTitle(), noticeType);
            }

            String defaultTitle = uniqueTitle();
            String defaultId = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"title\":\"" + defaultTitle + "\",\"content\":\"default type\"}")
                    .when().post("/v1/notices")
                    .then().statusCode(201)
                    .body("data.noticeType", is("NOTICE"))
                    .extract().path("data.id");
            noticeIds.add(defaultId);

            String updateTitle = uniqueTitle();
            String updateId = createNotice(token, updateTitle, "BASE");
            noticeIds.add(updateId);
            String validUpdateType = "😀".repeat(32);
            given().auth().oauth2(token).contentType(JSON)
                    .body(json(updateTitle, validUpdateType))
                    .when().put("/v1/notices/" + updateId)
                    .then().statusCode(200)
                    .body("data.noticeType", is(validUpdateType));

            given().auth().oauth2(token).contentType(JSON)
                    .body(json(updateTitle, ascii33))
                    .when().put("/v1/notices/" + updateId)
                    .then().statusCode(422)
                    .body("error.code", is("notice_type_invalid"));
            assertNoticeType(token, updateTitle, validUpdateType);

            // 未提供 noticeType 时沿用实体现有值，保持 Native 的 null 语义。
            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"title\":\"" + updateTitle + "\",\"content\":\"null type\"}")
                    .when().put("/v1/notices/" + updateId)
                    .then().statusCode(200)
                    .body("data.noticeType", is(validUpdateType));

            // 校验先于资源查找，非法类型不能因不存在的 ID 被误报为 404。
            given().auth().oauth2(token).contentType(JSON)
                    .body(json("missing", ascii33))
                    .when().put("/v1/notices/" + UUID.randomUUID())
                    .then().statusCode(422)
                    .body("error.code", is("notice_type_invalid"));
        } finally {
            for (String id : noticeIds) {
                given().auth().oauth2(token).when().delete("/v1/notices/" + id);
            }
        }
    }

    private static String createNotice(String token, String title, String noticeType) {
        return given().auth().oauth2(token).contentType(JSON)
                .body(json(title, noticeType))
                .when().post("/v1/notices")
                .then().statusCode(201)
                .body("data.noticeType", is(noticeType))
                .extract().path("data.id");
    }

    private static void rejectCreateWithoutSideEffect(String token, String title, String noticeType) {
        given().auth().oauth2(token).contentType(JSON)
                .body(json(title, noticeType))
                .when().post("/v1/notices")
                .then().statusCode(422)
                .body("error.code", is("notice_type_invalid"));
        given().auth().oauth2(token)
                .queryParam("page", 1).queryParam("size", 20).queryParam("keyword", title)
                .when().get("/v1/notices/manage")
                .then().statusCode(200)
                .body("data.items", hasSize(0))
                .body("data.total", is(0));
    }

    private static void assertNoticeType(String token, String title, String expectedType) {
        given().auth().oauth2(token)
                .queryParam("page", 1).queryParam("size", 20).queryParam("keyword", title)
                .when().get("/v1/notices/manage")
                .then().statusCode(200)
                .body("data.items", hasSize(1))
                .body("data.items[0].noticeType", is(expectedType));
    }

    private static String json(String title, String noticeType) {
        return "{\"title\":\"" + title + "\",\"content\":\"boundary content\",\"noticeType\":\""
                + noticeType + "\"}";
    }

    private static String uniqueTitle() {
        return "notice-type-boundary-" + UUID.randomUUID().toString().replace("-", "");
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
