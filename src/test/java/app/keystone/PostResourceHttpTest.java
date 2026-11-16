package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.hasSize;

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
                    .body("{\"code\":\"" + code + "\",\"name\":\"岗位测试\",\"sortOrder\":10,\"enabled\":false}")
                    .when().post("/v1/posts")
                    .then().statusCode(201)
                    .body("data.code", is(code))
                    .body("data.enabled", is(false))
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

    @Test
    void listSupportsServerPaginationAndFiltersWhileKeepingLegacyArray() {
        String token = login("admin", "password");
        Object legacy = given().auth().oauth2(token)
                .when().get("/v1/posts")
                .then().statusCode(200).extract().path("data");
        org.junit.jupiter.api.Assertions.assertInstanceOf(java.util.List.class, legacy);

        java.util.List<String> ids = new java.util.ArrayList<>();
        String marker = "HTTP_POST_PAGE_" + System.nanoTime();
        for (int index = 1; index <= 3; index++) {
            String id = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"code\":\"" + marker + "_" + index + "\",\"name\":\"" + marker + "\",\"sortOrder\":10,\"enabled\":" + (index != 3) + "}")
                    .when().post("/v1/posts")
                    .then().statusCode(201).extract().path("data.id");
            ids.add(id);
        }

        given().auth().oauth2(token)
                .when().get("/v1/posts?page=2&size=2&keyword=" + marker)
                .then().statusCode(200)
                .body("data.page", is(2))
                .body("data.size", is(2))
                .body("data.total", is(3))
                .body("data.items", hasSize(1));

        given().auth().oauth2(token)
                .when().get("/v1/posts?page=1&size=20&status=disabled&keyword=" + marker)
                .then().statusCode(200)
                .body("data.total", is(1))
                .body("data.items", hasSize(1));

        for (String id : ids) {
            given().auth().oauth2(token).when().delete("/v1/posts/" + id).then().statusCode(200);
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
