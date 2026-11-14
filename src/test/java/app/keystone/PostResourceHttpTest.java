package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

/** 通过真实 MySQL HTTP 链路验证岗位创建、更新、导出和删除。 */
@QuarkusTest
class PostResourceHttpTest extends AuthTestFixture {
    @Test
    void administratorCanManagePostLifecycle() {
        String admin = login("admin", "password");
        String postId = null;
        try {
            String code = "HTTP_POST_" + System.nanoTime();
            postId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + code + "\",\"name\":\"岗位测试\",\"sortOrder\":10}")
                    .when().post("/v1/posts")
                    .then().statusCode(201)
                    .body("data.code", is(code))
                    .extract().path("data.id");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"name\":\"岗位已更新\",\"sortOrder\":20,\"enabled\":false}")
                    .when().put("/v1/posts/" + postId)
                    .then().statusCode(200)
                    .body("data.name", is("岗位已更新"))
                    .body("data.enabled", is(false));

            given().auth().oauth2(admin)
                    .when().get("/v1/posts/export")
                    .then().statusCode(200)
                    .contentType(containsString("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                    .header("Content-Disposition", containsString("posts.xlsx"));

            given().auth().oauth2(admin)
                    .when().delete("/v1/posts/" + postId)
                    .then().statusCode(200)
                    .body("data.deleted", is(true));
            postId = null;
        } finally {
            if (postId != null) {
                given().auth().oauth2(admin).when().delete("/v1/posts/" + postId).then().statusCode(200);
            }
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
