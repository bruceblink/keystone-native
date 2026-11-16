package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 验证角色成员的查询、分配、撤销和批量失败回滚边界。 */
@QuarkusTest
class RoleResourceHttpTest extends AuthTestFixture {
    /** 通过真实 HTTP 验证角色自身的创建、更新、权限绑定和删除生命周期。 */
    @Test
    void administratorCanManageRoleLifecycle() {
        String admin = login("admin", "password");
        String roleId = null;
        try {
            String roleCode = "HTTP_ROLE_LIFECYCLE_" + System.nanoTime();
            roleId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + roleCode + "\",\"name\":\"Lifecycle role\",\"enabled\":false}")
                    .when().post("/v1/roles")
                    .then().statusCode(201)
                    .body("data.code", is(roleCode))
                    .body("data.enabled", is(false))
                    .extract().path("data.id");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"name\":\"Lifecycle role updated\",\"enabled\":true}")
                    .when().put("/v1/roles/" + roleId)
                    .then().statusCode(200)
                    .body("data.name", is("Lifecycle role updated"))
                    .body("data.enabled", is(true));

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"permissions\":[\"user:read\"]}")
                    .when().put("/v1/roles/" + roleId + "/permissions")
                    .then().statusCode(200)
                    .body("data.updated", is(true));

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles/" + roleId)
                    .then().statusCode(200)
                    .body("data.deleted", is(true));
            roleId = null;
        } finally {
            if (roleId != null) {
                given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
            }
        }
    }

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

    @Test
    void administratorBatchRoleDeleteRollsBackMissingTargetAndDeduplicatesIds() {
        String admin = login("admin", "password");
        String firstId = null;
        String secondId = null;
        try {
            firstId = createRole(admin, "HTTP_ROLE_BATCH_ONE_" + System.nanoTime());
            secondId = createRole(admin, "HTTP_ROLE_BATCH_TWO_" + System.nanoTime());
            String missing = UUID.randomUUID().toString();

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles?ids=" + firstId + "," + missing + "," + secondId)
                    .then().statusCode(404);
            List<String> afterRejected = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            assertTrue(afterRejected.contains(firstId));
            assertTrue(afterRejected.contains(secondId));

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles?ids=" + firstId + "," + firstId + "," + secondId)
                    .then().statusCode(200)
                    .body("data.deleted", is(2));
            firstId = null;
            secondId = null;
        } finally {
            if (firstId != null) given().auth().oauth2(admin).when().delete("/v1/roles/" + firstId);
            if (secondId != null) given().auth().oauth2(admin).when().delete("/v1/roles/" + secondId);
        }
    }

    /** 验证角色列表在兼容旧数组响应的同时支持服务端分页、关键字和状态筛选。 */
    @Test
    void administratorCanPageAndFilterRoles() {
        String admin = login("admin", "password");
        String roleId = null;
        String roleCode = "HTTP_ROLE_PAGE_" + System.nanoTime();
        String roleName = "Role pagination " + System.nanoTime();
        try {
            roleId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + roleCode + "\",\"name\":\"" + roleName + "\",\"enabled\":false}")
                    .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");

            List<String> legacy = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            assertTrue(legacy.contains(roleId));

            given().auth().oauth2(admin)
                    .when().get("/v1/roles?page=1&size=1")
                    .then().statusCode(200)
                    .body("data.page", is(1))
                    .body("data.size", is(1))
                    .body("data.items.size()", is(1))
                    .body("data.total", greaterThanOrEqualTo(1));

            given().auth().oauth2(admin)
                    .when().get("/v1/roles?keyword=" + roleCode.toLowerCase())
                    .then().statusCode(200)
                    .body("data.items.size()", is(1))
                    .body("data.items[0].id", is(roleId))
                    .body("data.items[0].code", is(roleCode));

            given().auth().oauth2(admin).queryParam("keyword", roleName)
                    .when().get("/v1/roles")
                    .then().statusCode(200)
                    .body("data.items.size()", is(1))
                    .body("data.items[0].id", is(roleId));

            List<Boolean> disabled = given().auth().oauth2(admin)
                    .when().get("/v1/roles?status=disabled")
                    .then().statusCode(200).extract().path("data.items.enabled");
            assertFalse(disabled.isEmpty());
            assertTrue(disabled.stream().allMatch(value -> !value));
            assertEquals(Boolean.FALSE, given().auth().oauth2(admin)
                    .when().get("/v1/roles?status=0&keyword=" + roleCode)
                    .then().statusCode(200).extract().path("data.items[0].enabled"));
        } finally {
            if (roleId != null) {
                given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
            }
        }
    }

    private static String createRole(String admin, String code) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"HTTP batch role\"}")
                .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
