package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 验证角色成员的查询、分配、撤销和批量失败回滚边界。 */
@QuarkusTest
class RoleResourceHttpTest extends AuthTestFixture {
    @Test
    void administratorCanAssignAndRevokeRoleUsers() {
        String admin = login("admin", "password");
        String roleId = null;
        String userId = null;
        try {
            String roleCode = "HTTP_ROLE_" + System.nanoTime();
            roleId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + roleCode + "\",\"name\":\"HTTP role members\"}")
                    .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
            userId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"role_member_" + System.nanoTime() + "\",\"password\":\"password\",\"displayName\":\"Role member\",\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\",\"not-a-uuid\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(422);
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\",\"" + UUID.randomUUID() + "\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(404);
            List<String> afterRejectedBatch = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            org.junit.jupiter.api.Assertions.assertFalse(afterRejectedBatch.contains(userId));

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\",\"" + userId + "\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).body("data.updated", is(true));
            List<String> allocated = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            org.junit.jupiter.api.Assertions.assertEquals(List.of(userId), allocated);

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\"]}")
                    .when().delete("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).body("data.updated", is(true));
            List<String> afterRevoke = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            org.junit.jupiter.api.Assertions.assertFalse(afterRevoke.contains(userId));
        } finally {
            if (userId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            }
            if (roleId != null) {
                given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
            }
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
