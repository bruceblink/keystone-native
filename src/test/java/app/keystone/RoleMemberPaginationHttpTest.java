package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.sql.PreparedStatement;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 通过真实 HTTP 和 MySQL 验证角色成员分页及旧数组兼容。 */
@QuarkusTest
class RoleMemberPaginationHttpTest extends AuthTestFixture {
    @Test
    void paginatesMembersAndPreservesLegacyArrayResponses() throws Exception {
        String admin = login("admin", "password");
        String roleCode = "ROLE_MEMBER_PAGE_" + System.nanoTime();
        String roleId = createRole(admin, roleCode);
        String firstUsername = "role_page_first_" + System.nanoTime();
        String secondUsername = "role_page_second_" + System.nanoTime();
        String firstUserId = createUser(admin, firstUsername, roleCode);
        String secondUserId = createUser(admin, secondUsername, roleCode);
        String availableUsername = "role_page_available_" + System.nanoTime();
        String availableUserId = createUser(admin, availableUsername, "USER");

        try {
            assertUserIdentity(admin, firstUserId, firstUsername);
            assertUserIdentity(admin, secondUserId, secondUsername);
            assertDatabaseIdentity(firstUserId, firstUsername);
            assertDatabaseIdentity(secondUserId, secondUsername);
            List<String> expected = List.of(firstUserId, secondUserId).stream()
                    .sorted(Comparator.reverseOrder())
                    .toList();
            Map<String, String> expectedUsernames = Map.of(
                    firstUserId, firstUsername,
                    secondUserId, secondUsername);

            List<String> legacyIds = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(expected, legacyIds);

            List<String> legacyIdsWithOldParameters = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("pageNum", 2)
                    .queryParam("pageSize", 1)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(expected, legacyIdsWithOldParameters);

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("page", 1)
                    .queryParam("size", 1)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(1))
                    .body("data.size", is(1))
                    .body("data.total", is(2))
                    .body("data.items", is(List.of(expected.get(0))));

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("page", 2)
                    .queryParam("size", 1)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(2))
                    .body("data.items", is(List.of(expected.get(1))));

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("page", -3)
                    .queryParam("size", 0)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(1))
                    .body("data.size", is(1))
                    .body("data.total", is(2));

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("page", "invalid")
                    .queryParam("size", "invalid")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(1))
                    .body("data.size", is(1))
                    .body("data.total", is(2));

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("size", 101)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(1))
                    .body("data.size", is(100))
                    .body("data.total", is(2));

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("page", Integer.MAX_VALUE)
                    .queryParam("size", 100)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(Integer.MAX_VALUE))
                    .body("data.size", is(100))
                    .body("data.total", is(2))
                    .body("data.items", is(List.of()));

            given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("include", "identity")
                    .queryParam("page", Integer.MAX_VALUE)
                    .queryParam("size", 100)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.page", is(Integer.MAX_VALUE))
                    .body("data.size", is(100))
                    .body("data.total", is(2))
                    .body("data.items", is(List.of()));

            for (int page = 1; page <= expected.size(); page++) {
                Map<String, Object> member = given().auth().oauth2(admin)
                        .queryParam("allocated", true)
                        .queryParam("include", "identity")
                        .queryParam("page", page)
                        .queryParam("size", 1)
                        .when().get("/v1/roles/" + roleId + "/users")
                        .then().statusCode(200)
                        .body("data.total", is(2))
                        .body("data.items.size()", is(1))
                        .extract().jsonPath().getMap("data.items[0]");
                String memberId = (String) member.get("id");
                String username = expectedUsernames.get(memberId);
                assertEquals(expected.get(page - 1), memberId);
                assertEquals(username, member.get("username"));
                assertEquals(username, member.get("displayName"));
                assertDatabaseIdentity(memberId, username);
            }

            given().auth().oauth2(admin)
                    .queryParam("allocated", false)
                    .queryParam("include", "identity")
                    .queryParam("username", availableUsername.toUpperCase())
                    .queryParam("page", 1)
                    .queryParam("size", 1)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .body("data.total", is(1))
                    .body("data.items.size()", is(1))
                    .body("data.items[0].id", is(availableUserId));

            List<Map<String, Object>> legacyIdentities = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("include", "identity")
                    .queryParam("pageNum", 2)
                    .queryParam("pageSize", 1)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().jsonPath().getList("data");
            assertEquals(expected, legacyIdentities.stream().map(item -> item.get("id")).toList());
        } finally {
            deleteUser(admin, firstUserId);
            deleteUser(admin, secondUserId);
            deleteUser(admin, availableUserId);
            deleteRole(admin, roleId);
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body(Map.of("username", username, "password", password, "forceLogin", true))
                .when().post("/v1/auth/login").then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private static String createRole(String admin, String code) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(Map.of("code", code, "name", "Role member page"))
                .when().post("/v1/roles").then().statusCode(201)
                .extract().path("data.id");
    }

    private static String createUser(String admin, String username, String roleCode) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(Map.of(
                        "username", username,
                        "password", "password",
                        "displayName", username,
                        "roleCodes", List.of(roleCode)))
                .when().post("/v1/users").then().statusCode(201)
                .extract().path("data.id");
    }

    private static void assertUserIdentity(String admin, String userId, String username) {
        given().auth().oauth2(admin)
                .when().get("/v1/users/" + userId)
                .then().statusCode(200)
                .body("data.username", is(username));
    }

    private void assertDatabaseIdentity(String userId, String username) throws Exception {
        try (var connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT username FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, userId);
            try (var result = statement.executeQuery()) {
                assertTrue(result.next());
                assertEquals(username, result.getString("username"));
            }
        }
    }

    private static void deleteUser(String admin, String userId) {
        given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
    }

    private static void deleteRole(String admin, String roleId) {
        given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
    }
}
